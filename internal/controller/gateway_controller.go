package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/greg2010/wireguard-gateway-operator/internal/gcpdiscovery"
	"github.com/greg2010/wireguard-gateway-operator/internal/gcpmembers"
	"github.com/greg2010/wireguard-gateway-operator/internal/link"
	"github.com/greg2010/wireguard-gateway-operator/internal/wg"
	wgnetv1alpha1 "github.com/greg2010/wireguard-gateway-operator/pkg/api/v1alpha1"
)

// gatewayFinalizer holds Gateway deletion until Crossplane has drained the cloud
// resources. The other children are reaped by owner-ref GC.
const gatewayFinalizer = "wgnet.dev/gateway-teardown"

// fieldOwner is the server-side-apply field manager for every applied object; a stable
// name keeps the operator from fighting Crossplane over defaulted fields.
const fieldOwner = client.FieldOwner("gateway-operator")

const (
	conditionReady = "Ready"

	reasonProvisioning    = "Provisioning"
	reasonReady           = "Ready"
	reasonReconcileFailed = "ReconcileFailed"
	reasonTerminating     = "Terminating"

	// actionReconcile is the action verb on emitted failure events. The events API
	// requires an UpperCamelCase action describing what the controller was doing.
	actionReconcile = "Reconcile"

	// Forward-validation Ready=False reasons. Each reflects external state a backend
	// change can clear without a spec edit, so all are transient.
	reasonCrossNamespaceForwardDenied = "CrossNamespaceForwardDenied"
	reasonTargetNamespaceNotFound     = "TargetNamespaceNotFound"
	reasonUnsupportedServiceType      = "UnsupportedServiceType"
	reasonServiceNotFound             = "ServiceNotFound"
	reasonTargetPortNotListening      = "TargetPortNotListening"

	// GCP-fleet Ready=False reasons.
	reasonInvalidTunnelAddresses      = "InvalidTunnelAddresses"
	reasonInsufficientTunnelAddresses = "InsufficientTunnelAddresses"
	reasonReservedHealthPort          = "ReservedHealthPort"
	reasonMemberDiscoveryFailed       = "MemberDiscoveryFailed"
	reasonMembersNotReady             = "MembersNotReady"
)

// reasonUnresolvedBackendPort is event-only, never a Ready reason: the forward stays
// valid, but its named targetPort widens the link's egress rule to the whole protocol.
const reasonUnresolvedBackendPort = "UnresolvedBackendPort"

// reasonMemberCleanupBlocked is an event-only reason: a blocked departure is reported on the
// member's own status.gcp.members entry, never in the Ready condition.
const reasonMemberCleanupBlocked = "MemberCleanupBlocked"

// crossNamespaceIngressLabel is the consent label a target namespace must carry before a
// Gateway elsewhere may forward public traffic into it.
const (
	crossNamespaceIngressLabel = "wgnet.dev/allow-gateway-ingress"
	crossNamespaceIngressValue = "true"
)

// linkIDAnnotation records the allocated Local link id on the Gateway itself, so an id
// outlives a restore that keeps metadata and spec but drops status.
const linkIDAnnotation = "wgnet.dev/link-id"

// validationRequeueAfter is the transient backoff before re-checking an absent backend,
// kept separate from RequeueInterval (zero in tests) so it cannot spin a hot loop.
const validationRequeueAfter = 10 * time.Second

// Poll before steady state so the Lease tunnel annotation is observed soon after PodReady.
// The controller does not watch Leases.
const tunnelReadyPollInterval = 3 * time.Second

// KeyGenerator produces a WireGuard keypair. It is injected so tests can supply
// deterministic key material; production binds it to wg.GenerateKeypair.
type KeyGenerator func() (privateKey, publicKey string, err error)

// GatewayReconciler reconciles a Gateway into its XGatewayGCP composite, key Secrets,
// the link workload with its RBAC and NetworkPolicy, and an optional DNSEndpoint, then
// mirrors the composite's observed status back onto the Gateway.
type GatewayReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Config   Config
	Recorder events.EventRecorder

	// APIReader bypasses the manager cache for objects it never tracks: the shared
	// XGatewayNetwork, link Leases and holder pods. SetupWithManager binds it.
	APIReader client.Reader

	// GenerateKey supplies WireGuard keypairs. Nil defaults to wg.GenerateKeypair.
	GenerateKey KeyGenerator

	// unresolvedWarned maps a Gateway UID to the last warned unresolved-backend-port signature,
	// suppressing an identical Warning every requeue. In-memory: a restart warns once more.
	unresolvedWarned sync.Map

	// gcpCreds shares a client until its operator-wide credential bytes change.
	gcpCreds gcpCredentialCache

	gcpAddressRefreshed sync.Map
	now                 func() time.Time
}

// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=wgnet.dev,resources=gateways/finalizers,verbs=update
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaygcps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaygcps/status,verbs=get
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaynetworks,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=infra.wgnet.dev,resources=xgatewaynetworks/status,verbs=get
// +kubebuilder:rbac:groups="",resources=secrets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=secretmanager.gcp.m.upbound.io,resources=secrets;secretversions;secretiammembers,verbs=get
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=daemonsets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=bind,resourceNames=gateway-link-endpointslice-reader
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=externaldns.k8s.io,resources=dnsendpoints,verbs=create;get;patch;update
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile exposes exactly the valid forward subset and never provisions while every
// forward is invalid, but once provisioned keeps its VM through a backend outage.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var gw wgnetv1alpha1.Gateway
	if err := r.Get(ctx, req.NamespacedName, &gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !gw.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &gw)
	}

	if !controllerutil.ContainsFinalizer(&gw, gatewayFinalizer) {
		controllerutil.AddFinalizer(&gw, gatewayFinalizer)
		if err := r.Update(ctx, &gw); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}

	eligibleAddresses, tunnelOK, tunnelReason := tunnelAddresses(
		effectiveWGSubnet(&gw), effectiveWGGatewayAddress(&gw), effectiveWGLinkAddress(&gw))
	if !tunnelOK {
		r.warnInvalidTunnelAddresses(&gw, tunnelReason)
		if serr := r.mirrorStatusWithForwards(ctx, &gw, "", "", linkStatus{},
			readySignals{InvalidTunnelAddresses: true, InvalidTunnelMessage: tunnelReason}, nil); serr != nil {
			return ctrl.Result{}, fmt.Errorf("mirror status: %w", serr)
		}
		logger.V(1).Info("gateway not provisioned: invalid tunnel addresses", "reason", tunnelReason)
		return ctrl.Result{RequeueAfter: validationRequeueAfter}, nil
	}
	// Suppression covers a repeat of an unchanged state: once validation passes, the same
	// reason recurring later warns again.
	r.unresolvedWarned.Delete(invalidTunnelWarnKeyPrefix + unresolvedWarnKey(&gw))

	valid, invalid, err := r.classifyForwards(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "classify forwards", err)
	}

	provisioned, err := r.xgatewayGCPExists(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "check xgatewaygcp existence", err)
	}

	if err := r.ensureLinkID(ctx, &gw); err != nil {
		if errors.Is(err, errNoFreeLinkID) {
			return r.failReported(ctx, &gw, "allocate link id", err)
		}
		return r.fail(ctx, &gw, "allocate link id", err)
	}

	// Health-port validation requires the allocated local link ID.
	valid, invalid, rejectedOnHealthPort := rejectReservedHealthPort(&gw, valid, invalid)
	r.warnReservedHealthPort(&gw, rejectedOnHealthPort)

	// Provision only when validation leaves at least one usable forward.
	if len(valid) == 0 && !provisioned {
		// Read the link the healthy path's way: it may still hold its Lease and serve
		// the last applied config, and status.link must not blink on this pass.
		ls, lerr := r.linkStatusOf(ctx, &gw)
		if lerr != nil {
			return r.fail(ctx, &gw, "read link activity", lerr)
		}
		if serr := r.mirrorStatusWithForwards(ctx, &gw, "", "", ls,
			readySignals{InvalidForward: firstInvalidForward(invalid)}, nil); serr != nil {
			return ctrl.Result{}, fmt.Errorf("mirror status: %w", serr)
		}
		result := ctrl.Result{}
		if anyTransientReason(invalid) {
			result.RequeueAfter = validationRequeueAfter
		}
		logger.V(1).Info("gateway not provisioned: no valid forwards", "invalid", len(invalid))
		return result, nil
	}

	loadBalanced := gw.Spec.GCP.LoadBalancer != nil
	healthPort := effectiveHealthPort(&gw)

	// Read observed names before apply because roster rendering depends on them.
	observed, err := r.readXGatewayGCPStatus(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read xgatewaygcp status", err)
	}
	address, saEmail, message := observed.Address, observed.ServiceAccountEmail, observed.Message

	// Capacity decides before anything is written: over the bound no secret, no shared
	// network and no composite is touched this pass.
	if limit := capacity(effectiveWGSubnet(&gw)); loadBalanced && int(gw.Spec.GCP.Replicas) > limit {
		capacityMessage := fmt.Sprintf("spec.gcp.replicas %d exceeds capacity %d of spec.wireguard.subnet",
			gw.Spec.GCP.Replicas, limit)
		r.warnInsufficientTunnelAddresses(&gw, capacityMessage)
		if aerr := r.applyOverCapacityXGatewayGCP(ctx, &gw, forwardSpecs(valid), healthPort); aerr != nil {
			return r.fail(ctx, &gw, "ensure xgatewaygcp", aerr)
		}
		ls, lerr := r.linkStatusOf(ctx, &gw)
		if lerr != nil {
			return r.fail(ctx, &gw, "read link activity", lerr)
		}
		if serr := r.mirrorStatusWithForwards(ctx, &gw, address, saEmail, ls, readySignals{
			InvalidForward:       firstInvalidForward(invalid),
			LinkFaultReason:      ls.FaultReason,
			LinkFaultMessage:     ls.FaultMessage,
			LoadBalanced:         true,
			InsufficientCapacity: true,
			CapacityMessage:      capacityMessage,
			ProvisionMessage:     message,
		}, nil); serr != nil {
			return ctrl.Result{}, fmt.Errorf("mirror status: %w", serr)
		}
		logger.V(1).Info("gateway not provisioned: insufficient tunnel addresses",
			"replicas", gw.Spec.GCP.Replicas, "capacity", limit)
		return ctrl.Result{RequeueAfter: r.steadyRequeue(loadBalanced)}, nil
	}
	// As with the tunnel-address warning: a pass that fits releases the suppression.
	r.unresolvedWarned.Delete(capacityWarnKeyPrefix + unresolvedWarnKey(&gw))

	if err := r.ensureSecrets(ctx, &gw); err != nil {
		return r.fail(ctx, &gw, "ensure key secrets", err)
	}
	if err := r.ensureXGatewayNetwork(ctx); err != nil {
		return r.fail(ctx, &gw, "ensure shared network", err)
	}

	var result *gcpmembers.Result
	var discoveryFailed bool
	var discoveryMessage string
	if loadBalanced {
		result, discoveryFailed, discoveryMessage, err = r.reconcileMembers(ctx, &gw, observed.MIGName, eligibleAddresses)
		if err != nil {
			return r.fail(ctx, &gw, "reconcile gcp members", err)
		}
	} else {
		result, err = r.reconcileSingleMember(ctx, &gw, observed.InstanceName)
		if err != nil {
			return r.fail(ctx, &gw, "reconcile single instance member", err)
		}
	}

	if err := r.ensureXGatewayGCP(ctx, &gw, forwardSpecs(valid), loadBalanced, result, healthPort); err != nil {
		return r.fail(ctx, &gw, "ensure xgatewaygcp", err)
	}

	var fleetPeers []link.Peer
	switch {
	case loadBalanced && result != nil && !result.Unusable:
		fleetPeers = fleetLinkPeers(&gw, fillPeerListenPort(result.Peers, int(effectiveWireguardPort(&gw))))
	case loadBalanced:
		// A pass with no usable snapshot publishes no membership: keep the peers the last
		// usable pass applied rather than unpeering a live fleet.
		fleetPeers, err = r.appliedLinkPeers(ctx, &gw)
		if err != nil {
			return r.fail(ctx, &gw, "read applied link peers", err)
		}
	}

	var gatewayPublicKey string
	if !loadBalanced {
		gatewayPublicKey, err = r.readLinkPeerPublicKey(ctx, &gw)
		if err != nil {
			return r.fail(ctx, &gw, "read link peer public key", err)
		}
	}

	if err := r.ensureLink(ctx, &gw, address, valid, linkIdentityOf(&gw), gatewayPublicKey, fleetPeers, healthPort); err != nil {
		return r.fail(ctx, &gw, "ensure link", err)
	}

	if err := r.ensureDNSEndpoint(ctx, &gw, address); err != nil {
		return r.fail(ctx, &gw, "ensure dns endpoint", err)
	}

	ls, err := r.linkStatusOf(ctx, &gw)
	if err != nil {
		return r.fail(ctx, &gw, "read link activity", err)
	}

	ready := address != "" && ls.Active
	provisionAddress := ""
	if ready {
		provisionAddress = address
	}

	signals := readySignals{
		InvalidForward:   firstInvalidForward(invalid),
		LinkFaultReason:  ls.FaultReason,
		LinkFaultMessage: ls.FaultMessage,
		LoadBalanced:     loadBalanced,
		DiscoveryFailed:  discoveryFailed,
		DiscoveryMessage: discoveryMessage,
		PeerCount:        len(fleetPeers),
		MembersNotReady:  loadBalanced && !ls.Active,
		ProvisionAddress: provisionAddress,
		ProvisionMessage: message,
	}
	// status.gcp.members mirrors a fleet: the single-Instance branch's own record is
	// published through the composite roster and carries no membership status.
	var membersResult *gcpmembers.Result
	if loadBalanced {
		membersResult = result
	}
	if err := r.mirrorStatusWithForwards(ctx, &gw, address, saEmail, ls, signals, membersResult); err != nil {
		return ctrl.Result{}, fmt.Errorf("mirror status: %w", err)
	}

	// Transient invalid forwards requeue on the transient floor, independent of the
	// steady-state poll (which may be zero in tests).
	reconcileResult := ctrl.Result{RequeueAfter: r.steadyRequeue(loadBalanced)}
	if anyTransientReason(invalid) {
		reconcileResult.RequeueAfter = validationRequeueAfter
	}
	// Poll before steady state so the Lease tunnel annotation is observed soon after PodReady.
	// The controller does not watch Leases.
	if ls.PodReady && !ls.Active {
		reconcileResult.RequeueAfter = tunnelReadyPollInterval
	}

	logger.V(1).Info("reconciled gateway",
		"address", address, "linkActive", ls.Active, "activeNode", ls.Node, "linkFault", ls.FaultReason, "ready", ready,
		"valid", len(valid), "invalid", len(invalid))
	return reconcileResult, nil
}

// invalidForward is a forward classifyForwards rejected, paired with the
// Ready=False reason and a human-readable message naming the specific failure.
type invalidForward struct {
	reason  string
	message string
}

// forwardBackend pairs a valid forward with its backend port and Service port name.
// BackendPort is 0 for a named targetPort; ServicePortName is empty for an unnamed port.
type forwardBackend struct {
	Forward         wgnetv1alpha1.Forward
	BackendPort     int32
	ServicePortName string
}

func forwardSpecs(backends []forwardBackend) []wgnetv1alpha1.Forward {
	forwards := make([]wgnetv1alpha1.Forward, 0, len(backends))
	for _, b := range backends {
		forwards = append(forwards, b.Forward)
	}
	return forwards
}

// classifyForwards partitions forwards into valid and invalid, preserving spec order. A
// non-NotFound API error fails the reconcile rather than misclassifying a forward.
func (r *GatewayReconciler) classifyForwards(ctx context.Context, gw *wgnetv1alpha1.Gateway) (valid []forwardBackend, invalid []invalidForward, err error) {
	local := isLocal(gw)
	var unresolved []unresolvedBackend
	for _, f := range gw.Spec.Forwards {
		ns := effectiveForwardNamespace(f, gw)

		if ns != gw.Namespace {
			allowed, aerr := r.namespaceAllowsIngress(ctx, ns)
			switch {
			case apierrors.IsNotFound(aerr):
				invalid = append(invalid, invalidForward{reasonTargetNamespaceNotFound,
					fmt.Sprintf("forward target namespace %q does not exist", ns)})
				continue
			case aerr != nil:
				return nil, nil, fmt.Errorf("get target namespace %q: %w", ns, aerr)
			case !allowed:
				invalid = append(invalid, invalidForward{reasonCrossNamespaceForwardDenied,
					fmt.Sprintf("cross-namespace forward to %q denied: target namespace must carry label %s=%s",
						ns, crossNamespaceIngressLabel, crossNamespaceIngressValue)})
				continue
			}
		}

		var svc corev1.Service
		serr := r.APIReader.Get(ctx, client.ObjectKey{Namespace: ns, Name: f.Service}, &svc)
		switch {
		case apierrors.IsNotFound(serr):
			invalid = append(invalid, invalidForward{reasonServiceNotFound,
				fmt.Sprintf("forward backend Service %q in namespace %q not found yet", f.Service, ns)})
			continue
		case serr != nil:
			return nil, nil, fmt.Errorf("get forward Service %s/%s: %w", ns, f.Service, serr)
		}

		if msg := unsupportedServiceMessage(&svc, local); msg != "" {
			invalid = append(invalid, invalidForward{reasonUnsupportedServiceType, msg})
			continue
		}

		port := effectiveServicePort(f)
		sp := servicePortFor(&svc, port, corev1.Protocol(f.Protocol))
		if sp == nil {
			invalid = append(invalid, invalidForward{reasonTargetPortNotListening,
				fmt.Sprintf("forward backend Service %q in namespace %q does not publish %s port %d",
					f.Service, ns, f.Protocol, port)})
			continue
		}

		backendPort := backendPortOf(sp)
		// Local resolves a named targetPort through the EndpointSlice and runs without an
		// egress NetworkPolicy, so an unresolved port widens nothing there.
		if backendPort == 0 && !local {
			unresolved = append(unresolved, unresolvedBackend{
				service: f.Service, namespace: ns, targetPort: sp.TargetPort.String(), protocol: string(f.Protocol),
			})
		}

		valid = append(valid, forwardBackend{Forward: f, BackendPort: backendPort, ServicePortName: sp.Name})
	}
	r.warnUnresolvedBackendPorts(gw, unresolved)
	return valid, invalid, nil
}

// unresolvedBackend is a valid forward whose backend Service names its targetPort, so
// the link's egress rule widens to the whole protocol.
type unresolvedBackend struct {
	service    string
	namespace  string
	targetPort string
	protocol   string
}

// warnUnresolvedBackendPorts emits one Warning per unresolved backend, only when the set
// changed: the condition is steady state, so every pass would otherwise re-emit it.
func (r *GatewayReconciler) warnUnresolvedBackendPorts(gw *wgnetv1alpha1.Gateway, unresolved []unresolvedBackend) {
	if r.Recorder == nil {
		return
	}

	key := unresolvedWarnKey(gw)
	if len(unresolved) == 0 {
		r.unresolvedWarned.Delete(key)
		return
	}

	signature := fmt.Sprintf("%v", unresolved)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == signature {
		return
	}
	r.unresolvedWarned.Store(key, signature)

	for _, u := range unresolved {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonUnresolvedBackendPort, actionReconcile,
			"forward backend Service %q in namespace %q names its targetPort %q: the link's egress policy allows every %s port to the backend rather than that one",
			u.service, u.namespace, u.targetPort, u.protocol)
	}
}

// unresolvedWarnKey identifies a Gateway instance for unresolvedWarned, carrying the UID
// so a recreated same-named Gateway does not inherit its predecessor's suppression.
func unresolvedWarnKey(gw *wgnetv1alpha1.Gateway) string {
	return client.ObjectKeyFromObject(gw).String() + "/" + string(gw.UID)
}

// servicePortFor returns the port svc publishes for port and proto, or nil. It matches
// spec.ports[].port, not the containerPort; an empty protocol defaults to TCP.
func servicePortFor(svc *corev1.Service, port int32, proto corev1.Protocol) *corev1.ServicePort {
	for i := range svc.Spec.Ports {
		p := &svc.Spec.Ports[i]
		svcProto := p.Protocol
		if svcProto == "" {
			svcProto = corev1.ProtocolTCP
		}
		if p.Port == port && svcProto == proto {
			return p
		}
	}
	return nil
}

// backendPortOf is sp's numeric targetPort. A named targetPort yields 0: resolving it
// needs the backing EndpointSlices. An unset one is defaulted by the API server.
func backendPortOf(sp *corev1.ServicePort) int32 {
	if sp.TargetPort.Type == intstr.String {
		return 0
	}
	return sp.TargetPort.IntVal
}

// anyTransientReason reports whether any invalid forward can clear without a spec edit.
// Reasons are enumerated so a permanent one is excluded by default.
func anyTransientReason(invalid []invalidForward) bool {
	for _, inv := range invalid {
		switch inv.reason {
		case reasonServiceNotFound, reasonTargetPortNotListening, reasonTargetNamespaceNotFound,
			reasonCrossNamespaceForwardDenied, reasonUnsupportedServiceType:
			return true
		}
	}
	return false
}

// namespaceAllowsIngress reports whether the namespace carries the consent label. A
// NotFound is returned so the caller can tell a missing namespace from an unlabelled one.
func (r *GatewayReconciler) namespaceAllowsIngress(ctx context.Context, name string) (bool, error) {
	var ns corev1.Namespace
	if err := r.APIReader.Get(ctx, client.ObjectKey{Name: name}, &ns); err != nil {
		return false, err
	}
	return ns.Labels[crossNamespaceIngressLabel] == crossNamespaceIngressValue, nil
}

// unsupportedServiceMessage reports why svc cannot back a forward, or "" when it can.
// ExternalName publishes no endpoints; headless lacks the VIP Cluster mode DNATs to.
func unsupportedServiceMessage(svc *corev1.Service, local bool) string {
	switch {
	case svc.Spec.Type == corev1.ServiceTypeExternalName:
		return fmt.Sprintf("forward backend Service %q in namespace %q has unsupported type %q: an ExternalName Service publishes no endpoints to forward to",
			svc.Name, svc.Namespace, svc.Spec.Type)
	case !local && (svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == corev1.ClusterIPNone):
		return fmt.Sprintf("forward backend Service %q in namespace %q is headless: the Cluster traffic policy requires a ClusterIP to DNAT to, set spec.trafficPolicy to Local to forward to a headless Service",
			svc.Name, svc.Namespace)
	}
	return ""
}

// reconcileDelete waits for the XGatewayGCP to disappear before releasing the finalizer,
// so Crossplane drains GCP while the namespace still lives.
func (r *GatewayReconciler) reconcileDelete(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(gw, gatewayFinalizer) {
		return ctrl.Result{}, nil
	}

	xg := newXGatewayGCP()
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg)
	switch {
	case apierrors.IsNotFound(err):
		return r.releaseAfterSharedNetwork(ctx, gw)
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get xgatewaygcp for deletion: %w", err)
	}

	if xg.GetDeletionTimestamp().IsZero() {
		if err := r.Delete(ctx, xg); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete xgatewaygcp: %w", err)
		}
	}

	if changed := meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonTerminating,
		Message:            "waiting for xgatewaygcp to finish draining cloud resources",
		ObservedGeneration: gw.Generation,
	}); changed {
		if err := r.Status().Update(ctx, gw); err != nil {
			return ctrl.Result{}, fmt.Errorf("update gateway status: %w", err)
		}
	}

	return ctrl.Result{RequeueAfter: validationRequeueAfter}, nil
}

// releaseAfterSharedNetwork refcounts the shared VPC: it releases the finalizer at once
// while any Gateway remains, and on the last delete holds until the network is gone.
func (r *GatewayReconciler) releaseAfterSharedNetwork(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	var gateways wgnetv1alpha1.GatewayList
	if err := r.APIReader.List(ctx, &gateways); err != nil {
		return ctrl.Result{}, fmt.Errorf("list gateways for shared-network refcount: %w", err)
	}

	remaining := 0
	for i := range gateways.Items {
		if gateways.Items[i].DeletionTimestamp.IsZero() {
			remaining++
		}
	}

	if remaining > 0 {
		return r.releaseFinalizer(ctx, gw)
	}

	net := newXGatewayNetwork()
	err := r.APIReader.Get(ctx, client.ObjectKey{Name: r.Config.SharedNetworkName, Namespace: r.Config.PodNamespace}, net)
	switch {
	case apierrors.IsNotFound(err):
		return r.releaseFinalizer(ctx, gw)
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get shared network for deletion: %w", err)
	}

	if net.GetDeletionTimestamp().IsZero() {
		if err := r.Delete(ctx, net); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("delete shared network: %w", err)
		}
		if changed := meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonTerminating,
			Message:            "waiting for shared network to finish draining cloud resources",
			ObservedGeneration: gw.Generation,
		}); changed {
			if err := r.Status().Update(ctx, gw); err != nil {
				return ctrl.Result{}, fmt.Errorf("update gateway status: %w", err)
			}
		}
	}

	return ctrl.Result{RequeueAfter: validationRequeueAfter}, nil
}

// Deletes the link workload before the Lease and ClusterRoleBinding: nothing owner-reaps the Lease
// and a live elector re-creates it. The pod wait is bounded so one stuck Terminating cannot strand.
func (r *GatewayReconciler) releaseFinalizer(ctx context.Context, gw *wgnetv1alpha1.Gateway) (ctrl.Result, error) {
	if err := r.deleteLinkWorkload(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}

	var pods corev1.PodList
	if err := r.APIReader.List(ctx, &pods,
		client.InNamespace(gw.Namespace), client.MatchingLabels(linkSelectorLabels(gw))); err != nil {
		return ctrl.Result{}, fmt.Errorf("list link pods for teardown: %w", err)
	}
	holding, stuck := partitionTerminatingLinkPods(pods.Items)
	if len(stuck) > 0 {
		log.FromContext(ctx).Info("proceeding with link teardown past pods stuck terminating",
			"pods", stuck, "reason", "deletionTimestamp older than the pod grace period plus slack",
			"slack", linkTeardownSlack.String())
	}
	if len(holding) > 0 {
		if err := r.markTerminatingOnLinkPods(ctx, gw, holding); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: linkTeardownRequeueAfter}, nil
	}

	if err := r.deleteLinkLease(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.deleteLinkClusterRoleBinding(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}
	controllerutil.RemoveFinalizer(gw, gatewayFinalizer)
	if err := r.Update(ctx, gw); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}
	r.dropWarnSuppression(gw)
	r.gcpAddressRefreshed.Delete(gatewayRefreshKey(gw))
	return ctrl.Result{}, nil
}

// dropWarnSuppression clears the suppression entries the Gateway being deleted owns, so a
// Gateway re-created under the same name warns again on the same condition.
func (r *GatewayReconciler) dropWarnSuppression(gw *wgnetv1alpha1.Gateway) {
	key := unresolvedWarnKey(gw)
	r.unresolvedWarned.Delete(key)
	r.unresolvedWarned.Delete(blockedCleanupWarnKeyPrefix + key)
	r.unresolvedWarned.Delete(invalidTunnelWarnKeyPrefix + key)
	r.unresolvedWarned.Delete(capacityWarnKeyPrefix + key)
	r.unresolvedWarned.Delete(reservedHealthPortWarnKeyPrefix + key)
}

// linkTeardownRequeueAfter paces the wait for the link pods to exit. Nothing watches
// those pods, so this requeue timer is the only trigger that re-checks them.
const linkTeardownRequeueAfter = 2 * time.Second

// linkTeardownSlack pads each pod's grace period before teardown stops waiting on it. A pod on a
// partitioned node stays Terminating until its Node goes away. Var so tests can shorten it.
var linkTeardownSlack = 30 * time.Second

// partitionTerminatingLinkPods splits link pods into those teardown waits for and those deleted
// longer ago than their grace period plus linkTeardownSlack. Sorted, so messages stay stable.
func partitionTerminatingLinkPods(pods []corev1.Pod) (holding, stuck []string) {
	for i := range pods {
		pod := &pods[i]
		deletedAt := pod.DeletionTimestamp
		grace := int64(corev1.DefaultTerminationGracePeriodSeconds)
		if pod.Spec.TerminationGracePeriodSeconds != nil {
			grace = *pod.Spec.TerminationGracePeriodSeconds
		}
		if deletedAt.IsZero() || time.Since(deletedAt.Time) <= time.Duration(grace)*time.Second+linkTeardownSlack {
			holding = append(holding, pod.Name)
			continue
		}
		stuck = append(stuck, pod.Name)
	}
	slices.Sort(holding)
	slices.Sort(stuck)
	return holding, stuck
}

// markTerminatingOnLinkPods publishes why the delete is still held, so a Gateway waiting
// on its link pods names them rather than showing a stale condition from before the delete.
func (r *GatewayReconciler) markTerminatingOnLinkPods(ctx context.Context, gw *wgnetv1alpha1.Gateway, pods []string) error {
	if changed := meta.SetStatusCondition(&gw.Status.Conditions, metav1.Condition{
		Type:               conditionReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonTerminating,
		Message:            "waiting for link pods to exit: " + strings.Join(pods, ", "),
		ObservedGeneration: gw.Generation,
	}); changed {
		if err := r.Status().Update(ctx, gw); err != nil {
			return fmt.Errorf("update gateway status: %w", err)
		}
	}
	return nil
}

// deleteLinkWorkload removes the mode's link workload, tolerating a NotFound. Deleting it
// explicitly rather than leaving it to owner-ref GC stops the electors before the Lease reap.
func (r *GatewayReconciler) deleteLinkWorkload(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	objMeta := metav1.ObjectMeta{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	var workload client.Object = &appsv1.Deployment{ObjectMeta: objMeta}
	if isLocal(gw) {
		workload = &appsv1.DaemonSet{ObjectMeta: objMeta}
	}
	if err := r.Delete(ctx, workload, client.PropagationPolicy(metav1.DeletePropagationBackground)); err != nil &&
		!apierrors.IsNotFound(err) {
		return fmt.Errorf("delete link workload %s/%s: %w", objMeta.Namespace, objMeta.Name, err)
	}
	return nil
}

// deleteLinkLease removes the leader-election Lease the link pods create. It must run
// only once no link pod is left, or a live elector re-creates it.
func (r *GatewayReconciler) deleteLinkLease(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: linkComponentName(gw)},
	}
	if err := r.Delete(ctx, lease); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete link lease %s/%s: %w", lease.Namespace, lease.Name, err)
	}
	return nil
}

// errNoFreeLinkID reports that every id in 1..link.MaxLinkID is held. Only deleting a
// Local Gateway frees one, so it is surfaced on Ready instead of retried with backoff.
var errNoFreeLinkID = errors.New("no free link id")

// ensureLinkID records the Local link id in status and in linkIDAnnotation, which outlives a
// restore that drops status. A status id wins: it names node state a restarting link reclaims.
func (r *GatewayReconciler) ensureLinkID(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	if !isLocal(gw) {
		return nil
	}
	if gw.Status.Link.ID > 0 {
		return r.persistLinkIDAnnotation(ctx, gw, gw.Status.Link.ID)
	}

	var gateways wgnetv1alpha1.GatewayList
	if err := r.APIReader.List(ctx, &gateways); err != nil {
		return fmt.Errorf("list gateways for link id allocation: %w", err)
	}
	self := client.ObjectKeyFromObject(gw)

	id, ok := r.adoptableLinkID(ctx, gw, gateways.Items, self)
	if !ok {
		if id, ok = lowestFreeLinkID(gateways.Items, self); !ok {
			return errNoFreeLinkID
		}
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for link id update: %w", err)
		}
		if fresh.Status.Link.ID > 0 {
			id = fresh.Status.Link.ID
			return nil
		}
		fresh.Status.Link.ID = id
		if err := r.Status().Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway link id: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	gw.Status.Link.ID = id
	return r.persistLinkIDAnnotation(ctx, gw, id)
}

// adoptableLinkID reports the id gw's annotation claims when well-formed and unheld elsewhere.
// Rejections are logged: the Gateway then takes an id its node state is not named after.
func (r *GatewayReconciler) adoptableLinkID(ctx context.Context, gw *wgnetv1alpha1.Gateway, gateways []wgnetv1alpha1.Gateway, self client.ObjectKey) (int32, bool) {
	raw, present := gw.Annotations[linkIDAnnotation]
	if !present {
		return 0, false
	}
	logger := log.FromContext(ctx)
	claimed, err := parseLinkID(raw)
	if err != nil {
		logger.Info("ignoring link id annotation, allocating a fresh id",
			"gateway", self.String(), "annotation", raw, "reason", err.Error())
		return 0, false
	}
	if holder, taken := linkIDHolders(gateways, self)[claimed]; taken {
		logger.Info("ignoring link id annotation, allocating a fresh id",
			"gateway", self.String(), "annotation", raw, "reason", "held by "+holder.String())
		return 0, false
	}
	return claimed, true
}

// persistLinkIDAnnotation records id in gw's linkIDAnnotation, both on the server and on
// the in-memory copy. It is a no-op when the annotation already matches.
func (r *GatewayReconciler) persistLinkIDAnnotation(ctx context.Context, gw *wgnetv1alpha1.Gateway, id int32) error {
	want := strconv.FormatInt(int64(id), 10)
	if gw.Annotations[linkIDAnnotation] == want {
		return nil
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		if err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for link id annotation update: %w", err)
		}
		if fresh.Annotations[linkIDAnnotation] == want {
			return nil
		}
		if fresh.Annotations == nil {
			fresh.Annotations = make(map[string]string, 1)
		}
		fresh.Annotations[linkIDAnnotation] = want
		if err := r.Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway link id annotation: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}

	if gw.Annotations == nil {
		gw.Annotations = make(map[string]string, 1)
	}
	gw.Annotations[linkIDAnnotation] = want
	return nil
}

// parseLinkID reads an annotated id, rejecting anything outside 1..link.MaxLinkID.
func parseLinkID(raw string) (int32, error) {
	parsed, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("malformed link id annotation %q", raw)
	}
	if parsed < 1 || parsed > link.MaxLinkID {
		return 0, fmt.Errorf("link id annotation %q out of range 1..%d", raw, link.MaxLinkID)
	}
	return int32(parsed), nil
}

// linkIDHolders maps each held id to its Gateway, skipping self. Status id and annotated id both
// reserve: reallocating an annotated id would hand two links the same node-global names.
func linkIDHolders(gateways []wgnetv1alpha1.Gateway, self client.ObjectKey) map[int32]client.ObjectKey {
	holders := make(map[int32]client.ObjectKey, len(gateways))
	for i := range gateways {
		g := &gateways[i]
		key := client.ObjectKeyFromObject(g)
		if key == self {
			continue
		}
		if g.Status.Link.ID > 0 {
			holders[g.Status.Link.ID] = key
		}
		if raw, ok := g.Annotations[linkIDAnnotation]; ok {
			if id, err := parseLinkID(raw); err == nil {
				holders[id] = key
			}
		}
	}
	return holders
}

// lowestFreeLinkID returns the lowest id in 1..link.MaxLinkID held by no Gateway,
// skipping self. A single active operator serialises the allocation.
func lowestFreeLinkID(gateways []wgnetv1alpha1.Gateway, self client.ObjectKey) (int32, bool) {
	taken := linkIDHolders(gateways, self)
	for id := int32(1); id <= link.MaxLinkID; id++ {
		if _, ok := taken[id]; !ok {
			return id, true
		}
	}
	return 0, false
}

// ensureSecrets writes both key Secrets from one pair when either is missing.
func (r *GatewayReconciler) ensureSecrets(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	bundleExists, err := r.objectExists(ctx, gw.Namespace, bundleSecretName(gw), &corev1.Secret{})
	if err != nil {
		return err
	}
	linkExists, err := r.objectExists(ctx, gw.Namespace, linkSecretName(gw), &corev1.Secret{})
	if err != nil {
		return err
	}
	if bundleExists && linkExists {
		return nil
	}

	gen := r.GenerateKey
	if gen == nil {
		gen = wg.GenerateKeypair
	}
	gatewayPriv, gatewayPub, err := gen()
	if err != nil {
		return fmt.Errorf("generate gateway keypair: %w", err)
	}
	linkPriv, linkPub, err := gen()
	if err != nil {
		return fmt.Errorf("generate link keypair: %w", err)
	}

	if err := r.apply(ctx, gw, buildBundleSecret(gw, gatewayPriv, linkPub)); err != nil {
		return fmt.Errorf("write bundle secret: %w", err)
	}
	if err := r.apply(ctx, gw, buildLinkSecret(gw, linkPriv, gatewayPub)); err != nil {
		return fmt.Errorf("write link secret: %w", err)
	}
	return nil
}

// ensureXGatewayGCP server-side applies the composite without changing its status.
func (r *GatewayReconciler) ensureXGatewayGCP(ctx context.Context, gw *wgnetv1alpha1.Gateway, forwards []wgnetv1alpha1.Forward, loadBalanced bool, result *gcpmembers.Result, healthPort int) error {
	if result != nil {
		roster, err := r.passRoster(ctx, gw, result)
		if err != nil {
			return err
		}
		pass := *result
		pass.Roster = roster
		result = &pass
	}
	desired, err := buildXGatewayGCP(gw, r.Config, forwards, loadBalanced, result, healthPort)
	if err != nil {
		return err
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return fmt.Errorf("set xgatewaygcp owner reference: %w", err)
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal xgatewaygcp: %w", err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply xgatewaygcp: %w", err)
	}
	return nil
}

// applyOverCapacityXGatewayGCP preserves the existing target size and roster.
func (r *GatewayReconciler) applyOverCapacityXGatewayGCP(ctx context.Context, gw *wgnetv1alpha1.Gateway, forwards []wgnetv1alpha1.Forward, healthPort int) error {
	exists, err := r.xgatewayGCPExists(ctx, gw)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	targetSize, err := r.readXGatewayGCPTargetSize(ctx, gw)
	if err != nil {
		return err
	}
	// The unusable result retains the applied roster.
	return r.ensureXGatewayGCP(ctx, gw, forwards, true, &gcpmembers.Result{TargetSize: targetSize, Unusable: true}, healthPort)
}

// parseCredentialsSecretRef accepts an empty setting or exactly "<namespace>/<name>".
func parseCredentialsSecretRef(setting string) (namespace, name string, err error) {
	if setting == "" {
		return "", "", nil
	}
	namespace, name, found := strings.Cut(setting, "/")
	if !found || namespace == "" || name == "" || strings.Contains(name, "/") {
		return "", "", fmt.Errorf("gcp credentials secret %q: want \"<namespace>/<name>\"", setting)
	}
	return namespace, name, nil
}

// appliedLinkPeers reads the peer list already applied to the link ConfigMap, nil when there is
// no ConfigMap yet. It is the last usable pass's membership, which an unusable pass keeps.
func (r *GatewayReconciler) appliedLinkPeers(ctx context.Context, gw *wgnetv1alpha1.Gateway) ([]link.Peer, error) {
	var cm corev1.ConfigMap
	key := client.ObjectKey{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	if err := r.Get(ctx, key, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get link configmap %s: %w", key, err)
	}
	var rc link.RuntimeConfig
	if err := json.Unmarshal([]byte(cm.Data[linkConfigKey]), &rc); err != nil {
		return nil, fmt.Errorf("decode link runtime config %s: %w", key, err)
	}
	return rc.WireGuard.Peers, nil
}

// passRoster retains the composite roster when discovery is unusable.
func (r *GatewayReconciler) passRoster(ctx context.Context, gw *wgnetv1alpha1.Gateway, result *gcpmembers.Result) ([]gcpmembers.RosterEntry, error) {
	if !result.Unusable {
		return result.Roster, nil
	}
	xg := newXGatewayGCP()
	key := client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}
	if err := r.Get(ctx, key, xg); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get xgatewaygcp %s for applied members: %w", key, err)
	}
	raw, found, err := unstructured.NestedSlice(xg.Object, "spec", "members")
	if err != nil {
		return nil, fmt.Errorf("read spec.members of %s: %w", key, err)
	}
	if !found {
		return nil, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encode applied members of %s: %w", key, err)
	}
	var applied []struct {
		CloudSecretIAMMemberName string `json:"cloudSecretIamMemberName"`
		CloudSecretName          string `json:"cloudSecretName"`
		CloudSecretVersionName   string `json:"cloudSecretVersionName"`
		KubernetesSecretName     string `json:"kubernetesSecretName"`
		Name                     string `json:"name"`
		Slot                     int    `json:"slot"`
		TunnelAddress            string `json:"tunnelAddress"`
	}
	if err := json.Unmarshal(data, &applied); err != nil {
		return nil, fmt.Errorf("decode applied members of %s: %w", key, err)
	}
	entries := make([]gcpmembers.RosterEntry, 0, len(applied))
	for _, m := range applied {
		entries = append(entries, gcpmembers.RosterEntry{
			Name:          m.Name,
			Slot:          m.Slot,
			TunnelAddress: m.TunnelAddress,
			ManagedResourceNames: gcpmembers.ManagedResourceNames{
				KubernetesSecretName:     m.KubernetesSecretName,
				CloudSecretName:          m.CloudSecretName,
				CloudSecretVersionName:   m.CloudSecretVersionName,
				CloudSecretIAMMemberName: m.CloudSecretIAMMemberName,
			},
		})
	}
	return entries, nil
}

// fillPeerListenPort supplies the Gateway-wide port omitted by member reconciliation.
func fillPeerListenPort(peers []gcpmembers.Peer, port int) []gcpmembers.Peer {
	out := make([]gcpmembers.Peer, len(peers))
	for i, p := range peers {
		p.ListenPort = port
		out[i] = p
	}
	return out
}

// readLinkPeerPublicKey reads the single-instance peer key from the link Secret.
func (r *GatewayReconciler) readLinkPeerPublicKey(ctx context.Context, gw *wgnetv1alpha1.Gateway) (string, error) {
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: gw.Namespace, Name: linkSecretName(gw)}
	if err := r.Get(ctx, key, &secret); err != nil {
		return "", fmt.Errorf("get link secret %s for peer public key: %w", key, err)
	}
	return string(secret.Data[wg.LinkPeerPublicKey]), nil
}

// readXGatewayGCPTargetSize reads the composite's own current spec.targetSize (0 when the
// composite does not exist yet), gcpmembers.Reconcile's lastAcceptedTargetSize input.
func (r *GatewayReconciler) readXGatewayGCPTargetSize(ctx context.Context, gw *wgnetv1alpha1.Gateway) (int32, error) {
	xg := newXGatewayGCP()
	if err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg); err != nil {
		if apierrors.IsNotFound(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("get xgatewaygcp for target size: %w", err)
	}
	v, found, err := unstructured.NestedInt64(xg.Object, "spec", "targetSize")
	if err != nil {
		return 0, fmt.Errorf("read spec.targetSize: %w", err)
	}
	if !found {
		return 0, nil
	}
	return int32(v), nil
}

// steadyRequeue is the steady-state poll: a load-balanced Gateway re-lists its fleet no more
// often than GCPDiscoveryInterval, every other Gateway keeps the general RequeueInterval.
func (r *GatewayReconciler) steadyRequeue(loadBalanced bool) time.Duration {
	if loadBalanced && r.Config.GCPDiscoveryInterval > r.Config.RequeueInterval {
		return r.Config.GCPDiscoveryInterval
	}
	return r.Config.RequeueInterval
}

// readGatewayKeys reads the key material ensureSecrets generated once: the VM's own private
// key and the link's public key, both from the Gateway's bundle Secret.
func (r *GatewayReconciler) readGatewayKeys(ctx context.Context, gw *wgnetv1alpha1.Gateway) (gatewayPrivateKey, linkPublicKey string, err error) {
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: gw.Namespace, Name: bundleSecretName(gw)}
	if err := r.Get(ctx, key, &secret); err != nil {
		return "", "", fmt.Errorf("get bundle secret %s: %w", key, err)
	}
	gatewayPrivateKey, rest, _ := strings.Cut(string(secret.Data[wg.BundleKey]), "\n")
	linkPublicKey, _, _ = strings.Cut(rest, "\n")
	if gatewayPrivateKey == "" || linkPublicKey == "" {
		return "", "", fmt.Errorf("bundle secret %s carries no gateway key pair", key)
	}
	return gatewayPrivateKey, linkPublicKey, nil
}

// bundleInputs are the values every member's bundle payload carries beside its own key,
// address and slot: they are uniform across a Gateway.
func bundleInputs(gw *wgnetv1alpha1.Gateway, linkPublicKey string) gcpmembers.BundleInputs {
	return gcpmembers.BundleInputs{
		SubnetPrefix:   subnetPrefix(effectiveWGSubnet(gw)),
		PeerPublicKey:  linkPublicKey,
		PeerAllowedIPs: effectiveWGLinkAddress(gw) + "/32",
	}
}

// reconcileSingleMember retains the applied roster until an instance name is observed.
func (r *GatewayReconciler) reconcileSingleMember(ctx context.Context, gw *wgnetv1alpha1.Gateway, instanceName string) (*gcpmembers.Result, error) {
	if instanceName == "" {
		return &gcpmembers.Result{Unusable: true}, nil
	}
	gatewayPrivateKey, linkPublicKey, err := r.readGatewayKeys(ctx, gw)
	if err != nil {
		return nil, err
	}
	gatewayPublicKey, err := r.readLinkPeerPublicKey(ctx, gw)
	if err != nil {
		return nil, err
	}
	deps := gcpmembers.NewKubernetesDeps(r.Client, r.APIReader, gw.UID, gw.Spec.GCP.ProjectID)
	res, err := gcpmembers.ReconcileSingle(ctx, deps, string(gw.UID), gw.Namespace, gw.Name,
		gw.Spec.GCP.ProjectID, instanceName, effectiveWGGatewayAddress(gw),
		gatewayPrivateKey, gatewayPublicKey, bundleInputs(gw, linkPublicKey))
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// reconcileMembers runs one discovery-and-allocation pass for a load-balanced Gateway.
func (r *GatewayReconciler) reconcileMembers(ctx context.Context, gw *wgnetv1alpha1.Gateway, migName string, eligibleAddresses []string) (result *gcpmembers.Result, discoveryFailed bool, discoveryMessage string, err error) {
	if migName == "" {
		waiting, werr := r.dependencyWaitResult(ctx, gw)
		return waiting, false, "", werr
	}

	deps := gcpmembers.NewKubernetesDeps(r.Client, r.APIReader, gw.UID, gw.Spec.GCP.ProjectID)
	names, nerr := deps.ListRecordNames(ctx, gw.Namespace, gw.Name)
	if nerr != nil {
		return nil, false, "", fmt.Errorf("list member records: %w", nerr)
	}
	records := make([]gcpmembers.Record, 0, len(names))
	for _, name := range names {
		rec, found, rerr := deps.GetRecord(ctx, gw.Namespace, gw.Name, name)
		if rerr != nil {
			return nil, false, "", fmt.Errorf("get member record %q: %w", name, rerr)
		}
		if found {
			records = append(records, *rec)
		}
	}
	recorded := discoveryRecorded(records)
	now := time.Now()
	if r.now != nil {
		now = r.now()
	}
	refreshNames := []string(nil)
	if gcpAddressRefreshDue(&r.gcpAddressRefreshed, gatewayRefreshKey(gw), now, r.Config.GCPAddressRefreshInterval) {
		refreshNames = names
	}

	var snap *gcpdiscovery.Snapshot
	credNamespace, credName, cerr := parseCredentialsSecretRef(r.Config.GCPCredentialsSecret)
	if cerr != nil {
		return nil, false, "", cerr
	}
	discClient, cerr := r.gcpCreds.clientFor(ctx, r.APIReader, credNamespace, credName, r.Config.GCPCredentialsKey)
	if cerr != nil {
		discoveryFailed = true
		discoveryMessage = cerr.Error()
	} else {
		listed, lerr := discClient.List(ctx, gw.Spec.GCP.ProjectID, gw.Spec.GCP.Region, migName, recorded, refreshNames)
		if lerr != nil {
			discoveryFailed = true
			discoveryMessage = lerr.Error()
		} else {
			snap = &listed
			r.gcpAddressRefreshed.Store(gatewayRefreshKey(gw), now)
		}
	}

	lastTargetSize, terr := r.readXGatewayGCPTargetSize(ctx, gw)
	if terr != nil {
		return nil, false, "", terr
	}
	_, linkPublicKey, kerr := r.readGatewayKeys(ctx, gw)
	if kerr != nil {
		return nil, false, "", kerr
	}
	res, rerr := gcpmembers.Reconcile(ctx, deps, string(gw.UID), gw.Namespace, gw.Name, gw.Spec.GCP.ProjectID,
		snap, gw.Spec.GCP.Replicas, capacity(effectiveWGSubnet(gw)), eligibleAddresses,
		effectiveWGGatewayAddress(gw), lastTargetSize, bundleInputs(gw, linkPublicKey))
	if rerr != nil {
		return nil, false, "", rerr
	}
	if res.Unusable && discoveryMessage == "" {
		discoveryFailed = true
		discoveryMessage = "gcp member discovery pass produced no usable snapshot"
	}
	// An unusable pass neither changes cleanup warnings nor releases suppression.
	if !res.Unusable {
		r.warnBlockedMemberCleanup(gw, blockedMemberCleanups(&res))
	}
	return &res, discoveryFailed, discoveryMessage, nil
}

// dependencyWaitResult retains applied membership while the MIG name is unavailable.
func (r *GatewayReconciler) dependencyWaitResult(ctx context.Context, gw *wgnetv1alpha1.Gateway) (*gcpmembers.Result, error) {
	exists, err := r.xgatewayGCPExists(ctx, gw)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	targetSize, err := r.readXGatewayGCPTargetSize(ctx, gw)
	if err != nil {
		return nil, err
	}
	return &gcpmembers.Result{TargetSize: targetSize, Unusable: true}, nil
}

// blockedCleanupWarnKeyPrefix distinguishes warnBlockedMemberCleanup's suppression entries
// from the other warn helpers' in the shared unresolvedWarned map.
const blockedCleanupWarnKeyPrefix = "member-cleanup/"

// blockedMemberCleanups are the members whose confirmation could not complete this pass:
// Departed carrying the message naming what blocks the release.
func blockedMemberCleanups(result *gcpmembers.Result) []wgnetv1alpha1.GatewayGCPMemberStatus {
	if result == nil {
		return nil
	}
	blocked := make([]wgnetv1alpha1.GatewayGCPMemberStatus, 0, len(result.Members))
	for _, m := range result.Members {
		if m.State == wgnetv1alpha1.GatewayGCPMemberDeparted && m.Message != "" {
			blocked = append(blocked, m)
		}
	}
	return blocked
}

// warnBlockedMemberCleanup emits one Warning per member whose departure cannot complete, only when
// the blocked set changed: the block persists until its cause clears, so a requeue must not warn.
func (r *GatewayReconciler) warnBlockedMemberCleanup(gw *wgnetv1alpha1.Gateway, blocked []wgnetv1alpha1.GatewayGCPMemberStatus) {
	if r.Recorder == nil {
		return
	}
	key := blockedCleanupWarnKeyPrefix + unresolvedWarnKey(gw)
	if len(blocked) == 0 {
		r.unresolvedWarned.Delete(key)
		return
	}
	signature := blockedCleanupSignature(blocked)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == signature {
		return
	}
	r.unresolvedWarned.Store(key, signature)
	for _, m := range blocked {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonMemberCleanupBlocked, actionReconcile,
			"member %q has departed but its cleanup cannot complete: %s", m.Name, m.Message)
	}
}

func blockedCleanupSignature(blocked []wgnetv1alpha1.GatewayGCPMemberStatus) string {
	parts := make([]string, 0, len(blocked))
	for _, m := range blocked {
		parts = append(parts, m.Name+"="+m.Message)
	}
	return strings.Join(parts, ",")
}

func discoveryRecorded(records []gcpmembers.Record) []gcpdiscovery.Recorded {
	recorded := make([]gcpdiscovery.Recorded, 0, len(records))
	for _, rec := range records {
		recorded = append(recorded, gcpdiscovery.Recorded{Name: rec.Name, ExternalAddress: rec.ExternalAddress, InstanceID: rec.InstanceID})
	}
	return recorded
}

func gatewayRefreshKey(gw *wgnetv1alpha1.Gateway) string { return gw.Namespace + "/" + gw.Name }

func gcpAddressRefreshDue(refreshed *sync.Map, key string, now time.Time, interval time.Duration) bool {
	last, found := refreshed.Load(key)
	if !found {
		return true
	}
	at, ok := last.(time.Time)
	if !ok {
		return true
	}
	return now.Sub(at) >= interval
}

// ensureXGatewayNetwork applies the singleton shared-VPC composite before anything
// references it. It is unowned and re-created here if a racing last-delete tore it down.
func (r *GatewayReconciler) ensureXGatewayNetwork(ctx context.Context) error {
	desired := buildXGatewayNetwork(r.Config)
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal xgatewaynetwork: %w", err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply xgatewaynetwork: %w", err)
	}
	return nil
}

// ensureLink applies common link resources and the mode-specific workload.
func (r *GatewayReconciler) ensureLink(ctx context.Context, gw *wgnetv1alpha1.Gateway, address string, backends []forwardBackend, ident *link.GatewayIdentity, gatewayPublicKey string, fleetPeers []link.Peer, healthPort int) error {
	if err := r.apply(ctx, gw, buildLinkServiceAccount(gw)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkRole(gw)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkRoleBinding(gw)); err != nil {
		return err
	}

	cm, err := buildLinkConfigMap(gw, address, backends, ident, gatewayPublicKey, fleetPeers, healthPort)
	if err != nil {
		return err
	}
	if err := r.apply(ctx, gw, cm); err != nil {
		return err
	}

	if ident != nil {
		if err := r.apply(ctx, nil, buildLinkClusterRoleBinding(gw)); err != nil {
			return err
		}
		return r.apply(ctx, gw, buildLinkDaemonSet(gw, r.Config, ident))
	}

	if err := r.apply(ctx, gw, buildLinkNetworkPolicy(gw, backends)); err != nil {
		return err
	}
	if err := r.apply(ctx, gw, buildLinkDeployment(gw, r.Config)); err != nil {
		return err
	}

	if effectiveLinkReplicas(gw) > 1 {
		return r.apply(ctx, gw, buildLinkPodDisruptionBudget(gw))
	}
	return r.deleteLinkPodDisruptionBudget(ctx, gw)
}

// deleteLinkPodDisruptionBudget removes the link PDB, tolerating a NotFound. It runs at
// a single replica so a scale-down cannot leave a PDB behind to block node drains.
func (r *GatewayReconciler) deleteLinkPodDisruptionBudget(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      linkComponentName(gw),
			Namespace: gw.Namespace,
		},
	}
	if err := r.Delete(ctx, pdb); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete link poddisruptionbudget: %w", err)
	}
	return nil
}

// deleteLinkClusterRoleBinding removes the EndpointSlice-reader binding, tolerating a
// NotFound so it can run unconditionally in a mode that never created one.
func (r *GatewayReconciler) deleteLinkClusterRoleBinding(ctx context.Context, gw *wgnetv1alpha1.Gateway) error {
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: linkClusterRoleBindingName(gw)},
	}
	if err := r.Delete(ctx, crb); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete link clusterrolebinding: %w", err)
	}
	return nil
}

// ensureDNSEndpoint applies the DNSEndpoint once hostnames and the address are known.
// It is owner-ref'd but not watched, so startup does not depend on the external-dns CRD.
func (r *GatewayReconciler) ensureDNSEndpoint(ctx context.Context, gw *wgnetv1alpha1.Gateway, address string) error {
	desired := buildDNSEndpoint(gw, address)
	if desired == nil {
		return nil
	}
	if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
		return fmt.Errorf("set dns endpoint owner reference: %w", err)
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal dns endpoint: %w", err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply dns endpoint: %w", err)
	}
	return nil
}

// xgatewayGCPExists reports whether the Gateway provisioned at least once, so it keeps
// its VM under an all-invalid forward set. Errors other than NotFound are surfaced.
func (r *GatewayReconciler) xgatewayGCPExists(ctx context.Context, gw *wgnetv1alpha1.Gateway) (bool, error) {
	xg := newXGatewayGCP()
	err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get xgatewaygcp: %w", err)
	}
	return true, nil
}

// compositeStatus holds observed Crossplane values used by reconciliation.
type compositeStatus struct {
	Address             string
	ServiceAccountEmail string
	Message             string
	MIGName             string
	InstanceName        string
}

// readXGatewayGCPStatus reads the composite's observed status. A missing composite yields
// zero values: the apply has not yet propagated.
func (r *GatewayReconciler) readXGatewayGCPStatus(ctx context.Context, gw *wgnetv1alpha1.Gateway) (compositeStatus, error) {
	xg := newXGatewayGCP()
	if err := r.Get(ctx, client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name}, xg); err != nil {
		if apierrors.IsNotFound(err) {
			return compositeStatus{}, nil
		}
		return compositeStatus{}, fmt.Errorf("get xgatewaygcp: %w", err)
	}
	var status compositeStatus
	into := []struct {
		field string
		dest  *string
	}{
		{"address", &status.Address},
		{"serviceAccountEmail", &status.ServiceAccountEmail},
		{"message", &status.Message},
		{"migName", &status.MIGName},
		{"instanceName", &status.InstanceName},
	}
	for _, f := range into {
		value, _, err := unstructured.NestedString(xg.Object, "status", f.field)
		if err != nil {
			return compositeStatus{}, fmt.Errorf("read status.%s: %w", f.field, err)
		}
		*f.dest = value
	}
	return status, nil
}

// linkStatus is what the operator observes about a Gateway's link from the Lease and
// the pod holding it.
type linkStatus struct {
	// Active requires both holder PodReady and its tunnel-ready annotation; idle standbys
	// are PodReady too, so readiness must use the Lease holder rather than availability.
	Active bool
	// PodReady is checked before the tunnel annotation; this window needs a faster requeue.
	// The holder's first Lease write reports the tunnel after the probe latches ready.
	PodReady bool
	// Node is the holder pod's node name, empty when there is no readable holder.
	Node string
	// FaultReason and FaultMessage carry the holder's link-fault annotations.
	FaultReason  string
	FaultMessage string
}

// knownLinkFaults are the fault reasons a link may publish. An unrecognised value is
// ignored rather than copied into the API-validated Ready condition reason.
var knownLinkFaults = func() map[string]bool {
	faults := link.KnownFaults()
	m := make(map[string]bool, len(faults))
	for _, reason := range faults {
		m[reason] = true
	}
	return m
}()

// maxFaultMessageBytes bounds the Lease fault message copied into the Ready condition;
// the API rejects messages beyond 32768 characters, turning a fault into a write loop.
const maxFaultMessageBytes = 4096

const faultMessageTruncationMarker = "... (truncated)"

// truncateFaultMessage shortens msg to maxFaultMessageBytes, cutting on a rune boundary
// so the result stays valid UTF-8 and the API server accepts it.
func truncateFaultMessage(msg string) string {
	if len(msg) <= maxFaultMessageBytes {
		return msg
	}
	cut := maxFaultMessageBytes - len(faultMessageTruncationMarker)
	for cut > 0 && !utf8.RuneStart(msg[cut]) {
		cut--
	}
	return msg[:cut] + faultMessageTruncationMarker
}

// linkStatusOf reports the Lease holder's readiness, node and fault; a missing holder is a zero
// value, not an error. It reads the holder, not the expiry, which fail-static leaves stale.
func (r *GatewayReconciler) linkStatusOf(ctx context.Context, gw *wgnetv1alpha1.Gateway) (linkStatus, error) {
	var lease coordinationv1.Lease
	leaseKey := client.ObjectKey{Namespace: gw.Namespace, Name: linkComponentName(gw)}
	if err := r.APIReader.Get(ctx, leaseKey, &lease); err != nil {
		if apierrors.IsNotFound(err) {
			return linkStatus{}, nil
		}
		return linkStatus{}, fmt.Errorf("get link lease %s: %w", leaseKey, err)
	}
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
		return linkStatus{}, nil
	}

	var ls linkStatus
	if reason := lease.Annotations[link.LeaseFaultAnnotation]; knownLinkFaults[reason] {
		ls.FaultReason = reason
		ls.FaultMessage = truncateFaultMessage(lease.Annotations[link.LeaseFaultMessageAnnotation])
		if ls.FaultMessage == "" {
			ls.FaultMessage = fmt.Sprintf("link reported %s", reason)
		}
	}

	var holder corev1.Pod
	holderKey := client.ObjectKey{Namespace: gw.Namespace, Name: *lease.Spec.HolderIdentity}
	if err := r.APIReader.Get(ctx, holderKey, &holder); err != nil {
		if apierrors.IsNotFound(err) {
			return ls, nil
		}
		return linkStatus{}, fmt.Errorf("get link lease holder pod %s: %w", holderKey, err)
	}
	ls.Node = holder.Spec.NodeName
	for _, cond := range holder.Status.Conditions {
		if cond.Type == corev1.PodReady {
			ls.PodReady = cond.Status == corev1.ConditionTrue
			break
		}
	}
	ls.Active = ls.PodReady && lease.Annotations[link.LeaseTunnelReadyAnnotation] == "true"
	return ls, nil
}

// readySignals holds the inputs to Ready-condition precedence.
type readySignals struct {
	InvalidTunnelAddresses bool
	InvalidTunnelMessage   string
	InvalidForward         *invalidForward // first invalid forward, nil when none
	LinkFaultReason        string
	LinkFaultMessage       string
	LoadBalanced           bool
	InsufficientCapacity   bool
	CapacityMessage        string
	DiscoveryFailed        bool
	DiscoveryMessage       string
	// PeerCount is how many peers this pass rendered into the link config. Read only when
	// loadBalanced: none means no fleet member has been observed yet.
	PeerCount        int
	MembersNotReady  bool // true only when loadBalanced and no member has a live session
	ProvisionAddress string
	ProvisionMessage string
}

// readyPrecedence returns the first applicable Ready-condition reason.
func readyPrecedence(in readySignals) (reason, message string, ready bool) {
	switch {
	case in.InvalidTunnelAddresses:
		return reasonInvalidTunnelAddresses, in.InvalidTunnelMessage, false
	case in.InvalidForward != nil:
		return in.InvalidForward.reason, in.InvalidForward.message, false
	case in.LinkFaultReason != "":
		return in.LinkFaultReason, in.LinkFaultMessage, false
	case in.LoadBalanced && in.InsufficientCapacity:
		return reasonInsufficientTunnelAddresses, in.CapacityMessage, false
	case in.DiscoveryFailed:
		return reasonMemberDiscoveryFailed, in.DiscoveryMessage, false
	case in.LoadBalanced && in.PeerCount == 0:
		return reasonMembersNotReady, "no fleet member observed yet", false
	case in.LoadBalanced && in.MembersNotReady:
		return reasonMembersNotReady, "no fleet member has a live wireguard session", false
	case in.ProvisionAddress != "":
		return reasonReady, "gateway address provisioned and active link tunnel up", true
	default:
		message = "waiting for gateway address and active link tunnel"
		if m := truncateFaultMessage(in.ProvisionMessage); m != "" {
			message += ": " + m
		}
		return reasonProvisioning, message, false
	}
}

// mirrorStatusWithForwards writes changed Gateway status while retaining unusable members.
func (r *GatewayReconciler) mirrorStatusWithForwards(ctx context.Context, gw *wgnetv1alpha1.Gateway, address, saEmail string, ls linkStatus, signals readySignals, result *gcpmembers.Result) error {
	reason, message, ready := readyPrecedence(signals)
	cond := metav1.Condition{Type: conditionReady, Reason: reason, Message: message}
	if ready {
		cond.Status = metav1.ConditionTrue
	} else {
		cond.Status = metav1.ConditionFalse
	}

	// Re-read after SSA because its resourceVersion may be stale.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Use the uncached reader so a retry does not resubmit a stale object.
		reader := r.APIReader
		if reader == nil {
			reader = r.Client
		}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for status update: %w", err)
		}

		// A concurrent spec edit requires the fresh observed generation.
		cond.ObservedGeneration = fresh.Generation

		prevAddress := fresh.Status.Address
		prevSAEmail := fresh.Status.ServiceAccountEmail
		prevNode := fresh.Status.Link.ActiveNode
		fresh.Status.Address = address
		fresh.Status.ServiceAccountEmail = saEmail
		fresh.Status.Link.ActiveNode = ls.Node

		membersChanged := false
		if result != nil && !result.Unusable {
			membersChanged = !slices.EqualFunc(fresh.Status.GCP.Members, result.Members,
				func(a, b wgnetv1alpha1.GatewayGCPMemberStatus) bool { return a == b })
			fresh.Status.GCP.Members = result.Members
		}

		conditionChanged := meta.SetStatusCondition(&fresh.Status.Conditions, cond)

		if prevAddress == address && prevSAEmail == saEmail && prevNode == ls.Node && !conditionChanged && !membersChanged {
			return nil
		}

		if err := r.Status().Update(ctx, &fresh); err != nil {
			return fmt.Errorf("update gateway status: %w", err)
		}
		return nil
	})
}

// invalidForwardsMessage joins the per-forward messages into one Ready condition line,
// so kubectl alone shows which forwards are rejected and why.
func invalidForwardsMessage(invalid []invalidForward) string {
	parts := make([]string, 0, len(invalid))
	for _, inv := range invalid {
		parts = append(parts, inv.message)
	}
	return fmt.Sprintf("%d forward(s) invalid: %s", len(invalid), strings.Join(parts, "; "))
}

// firstInvalidForward preserves the first reason and all rejection messages.
func firstInvalidForward(invalid []invalidForward) *invalidForward {
	if len(invalid) == 0 {
		return nil
	}
	return &invalidForward{reason: invalid[0].reason, message: invalidForwardsMessage(invalid)}
}

// rejectReservedHealthPort rejects local TCP forwards colliding with the health port.
func rejectReservedHealthPort(gw *wgnetv1alpha1.Gateway, valid []forwardBackend, invalid []invalidForward) ([]forwardBackend, []invalidForward, []wgnetv1alpha1.Forward) {
	ident := linkIdentityOf(gw)
	if ident == nil {
		return valid, invalid, nil
	}
	var rejected []wgnetv1alpha1.Forward
	stillValid := make([]forwardBackend, 0, len(valid))
	for _, b := range valid {
		if b.Forward.Protocol == wgnetv1alpha1.ProtocolTCP && int(b.Forward.Port) == ident.HealthPort {
			invalid = append(invalid, invalidForward{reasonReservedHealthPort,
				fmt.Sprintf("forward TCP port %d collides with this Local gateway's own health port", ident.HealthPort)})
			rejected = append(rejected, b.Forward)
			continue
		}
		stillValid = append(stillValid, b)
	}
	return stillValid, invalid, rejected
}

// reservedHealthPortWarnKeyPrefix distinguishes warnReservedHealthPort's suppression entries
// from the other warn helpers' in the shared unresolvedWarned map.
const reservedHealthPortWarnKeyPrefix = "health-port/"

// warnReservedHealthPort emits one Warning per forward rejected for taking the link's own health
// port, while the rejected set is unchanged, mirroring warnUnresolvedBackendPorts.
func (r *GatewayReconciler) warnReservedHealthPort(gw *wgnetv1alpha1.Gateway, rejected []wgnetv1alpha1.Forward) {
	if r.Recorder == nil {
		return
	}
	key := reservedHealthPortWarnKeyPrefix + unresolvedWarnKey(gw)
	if len(rejected) == 0 {
		r.unresolvedWarned.Delete(key)
		return
	}
	signature := fmt.Sprintf("%v", rejected)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == signature {
		return
	}
	r.unresolvedWarned.Store(key, signature)
	for _, f := range rejected {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonReservedHealthPort, actionReconcile,
			"forward %s port %d to Service %q collides with this Local gateway's own health port",
			strings.ToLower(string(f.Protocol)), f.Port, f.Service)
	}
}

// invalidTunnelWarnKeyPrefix distinguishes warnInvalidTunnelAddresses' suppression entries
// from warnUnresolvedBackendPorts' in the shared unresolvedWarned map.
const invalidTunnelWarnKeyPrefix = "tunnel/"

// warnInvalidTunnelAddresses emits one Warning per distinct invalid-tunnel-address reason,
// suppressing a repeat while the reason stays unchanged, mirroring warnUnresolvedBackendPorts.
func (r *GatewayReconciler) warnInvalidTunnelAddresses(gw *wgnetv1alpha1.Gateway, reason string) {
	if r.Recorder == nil {
		return
	}
	key := invalidTunnelWarnKeyPrefix + unresolvedWarnKey(gw)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == reason {
		return
	}
	r.unresolvedWarned.Store(key, reason)
	r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonInvalidTunnelAddresses, actionReconcile, "%s", reason)
}

// capacityWarnKeyPrefix distinguishes warnInsufficientTunnelAddresses' suppression entries
// from the other warn helpers' in the shared unresolvedWarned map.
const capacityWarnKeyPrefix = "capacity/"

// warnInsufficientTunnelAddresses emits one Warning while the capacity message is unchanged,
// mirroring warnInvalidTunnelAddresses.
func (r *GatewayReconciler) warnInsufficientTunnelAddresses(gw *wgnetv1alpha1.Gateway, message string) {
	if r.Recorder == nil {
		return
	}
	key := capacityWarnKeyPrefix + unresolvedWarnKey(gw)
	if prev, ok := r.unresolvedWarned.Load(key); ok && prev == message {
		return
	}
	r.unresolvedWarned.Store(key, message)
	r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonInsufficientTunnelAddresses, actionReconcile, "%s", message)
}

// recordFailure emits the Warning and writes Ready=False for a reconcile failure,
// returning the wrapped cause and any status-write error.
func (r *GatewayReconciler) recordFailure(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (wrapped, statusErr error) {
	wrapped = fmt.Errorf("%s: %w", op, cause)
	if r.Recorder != nil {
		r.Recorder.Eventf(gw, nil, corev1.EventTypeWarning, reasonReconcileFailed, actionReconcile, "%s", wrapped.Error())
	}
	statusErr = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var fresh wgnetv1alpha1.Gateway
		// Re-Get uncached: the cache can still hold the copy whose resourceVersion lost
		// the conflict, so a cached retry would resubmit the same stale object forever.
		reader := r.APIReader
		if reader == nil {
			reader = r.Client
		}
		if err := reader.Get(ctx, client.ObjectKeyFromObject(gw), &fresh); err != nil {
			return fmt.Errorf("get gateway for status update: %w", err)
		}
		meta.SetStatusCondition(&fresh.Status.Conditions, metav1.Condition{
			Type:               conditionReady,
			Status:             metav1.ConditionFalse,
			Reason:             reasonReconcileFailed,
			Message:            wrapped.Error(),
			ObservedGeneration: fresh.Generation,
		})
		return r.Status().Update(ctx, &fresh)
	})
	return wrapped, statusErr
}

// fail records the error on the Gateway's Ready condition and surfaces it so the
// manager requeues with backoff.
func (r *GatewayReconciler) fail(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (ctrl.Result, error) {
	wrapped, uerr := r.recordFailure(ctx, gw, op, cause)
	if uerr != nil {
		return ctrl.Result{}, fmt.Errorf("%w; additionally failed to update status: %w", wrapped, uerr)
	}
	return ctrl.Result{}, wrapped
}

// failReported records the error like fail but requeues on the regular interval instead
// of returning it, for causes retrying cannot resolve.
func (r *GatewayReconciler) failReported(ctx context.Context, gw *wgnetv1alpha1.Gateway, op string, cause error) (ctrl.Result, error) {
	wrapped, uerr := r.recordFailure(ctx, gw, op, cause)
	if uerr != nil {
		return ctrl.Result{}, fmt.Errorf("%w; additionally failed to update status: %w", wrapped, uerr)
	}
	return ctrl.Result{RequeueAfter: r.Config.RequeueInterval}, nil
}

// objectExists reports whether the named object is present. probe is mutated by the Get;
// callers pass a fresh empty object of the desired kind.
func (r *GatewayReconciler) objectExists(ctx context.Context, namespace, name string, probe client.Object) (bool, error) {
	err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, probe)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("get %s/%s: %w", namespace, name, err)
	}
	return true, nil
}

// apply server-side-applies desired, filling the GVK from the scheme because typed builders omit
// the TypeMeta SSA requires. A nil gw stamps no ownerReference, as cluster-scoped children need.
func (r *GatewayReconciler) apply(ctx context.Context, gw *wgnetv1alpha1.Gateway, desired client.Object) error {
	gvks, _, err := r.Scheme.ObjectKinds(desired)
	if err != nil {
		return fmt.Errorf("gvk for %T: %w", desired, err)
	}
	desired.GetObjectKind().SetGroupVersionKind(gvks[0])
	if gw != nil {
		if err := controllerutil.SetControllerReference(gw, desired, r.Scheme); err != nil {
			return fmt.Errorf("set owner reference: %w", err)
		}
	}
	data, err := json.Marshal(desired)
	if err != nil {
		return fmt.Errorf("marshal %T: %w", desired, err)
	}
	if err := r.Patch(ctx, desired, client.RawPatch(types.ApplyPatchType, data), fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply %T: %w", desired, err)
	}
	return nil
}

// SetupWithManager registers the reconciler. The XGatewayGCP watch omits
// GenerationChangedPredicate so its status-only address writes trigger a reconcile.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.APIReader = mgr.GetAPIReader()

	xg := &unstructured.Unstructured{}
	xg.SetGroupVersionKind(XGatewayGCPGVK)

	genChanged := builder.WithPredicates(predicate.GenerationChangedPredicate{})

	return ctrl.NewControllerManagedBy(mgr).
		For(&wgnetv1alpha1.Gateway{}).
		Owns(&appsv1.Deployment{}).
		Owns(&appsv1.DaemonSet{}).
		Owns(&corev1.ConfigMap{}, genChanged).
		Owns(&corev1.Secret{}, genChanged).
		Owns(&networkingv1.NetworkPolicy{}, genChanged).
		Owns(xg).
		Watches(&corev1.Service{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForService)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.gatewaysForNamespace)).
		Complete(r)
}

// gatewaysForService maps a changed Service to the Gateways forwarding to it, matching
// on effective namespace so cross-namespace forwards resolve.
func (r *GatewayReconciler) gatewaysForService(ctx context.Context, obj client.Object) []reconcile.Request {
	var gateways wgnetv1alpha1.GatewayList
	if err := r.List(ctx, &gateways); err != nil {
		log.FromContext(ctx).Error(err, "list gateways for service watch", "service", client.ObjectKeyFromObject(obj))
		return nil
	}

	var requests []reconcile.Request
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		for _, f := range gw.Spec.Forwards {
			if f.Service == obj.GetName() && effectiveForwardNamespace(f, gw) == obj.GetNamespace() {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
				break
			}
		}
	}
	return requests
}

// gatewaysForNamespace maps a Namespace to the Gateways forwarding into it from elsewhere, so a
// consent-label edit re-classifies them. Same-namespace forwards need no consent.
func (r *GatewayReconciler) gatewaysForNamespace(ctx context.Context, obj client.Object) []reconcile.Request {
	var gateways wgnetv1alpha1.GatewayList
	if err := r.List(ctx, &gateways); err != nil {
		log.FromContext(ctx).Error(err, "list gateways for namespace watch", "namespace", obj.GetName())
		return nil
	}

	var requests []reconcile.Request
	for i := range gateways.Items {
		gw := &gateways.Items[i]
		for _, f := range gw.Spec.Forwards {
			ns := effectiveForwardNamespace(f, gw)
			if ns == obj.GetName() && ns != gw.Namespace {
				requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
				break
			}
		}
	}
	return requests
}
