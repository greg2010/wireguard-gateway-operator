package k8s

import (
	"context"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
)

func TestGatewayUID(t *testing.T) {
	gateway := func(uid string) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "wgnet.dev/v1alpha1",
			"kind":       "Gateway",
			"metadata": map[string]any{
				"name":      "gateway",
				"namespace": "test",
			},
		}}
		obj.SetGroupVersionKind(gatewayGVR.GroupVersion().WithKind("Gateway"))
		obj.SetNamespace("test")
		obj.SetName("gateway")
		obj.SetUID(types.UID(uid))
		return obj
	}

	tests := []struct {
		name    string
		object  *unstructured.Unstructured
		want    string
		wantErr string
	}{
		{name: "gateway with uid", object: gateway("gateway-uid"), want: "gateway-uid"},
		{name: "gateway without uid", object: gateway(""), wantErr: "gateway test/gateway has empty uid"},
		{name: "missing gateway", wantErr: "get gateway test/gateway"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			scheme.AddKnownTypeWithName(gatewayGVR.GroupVersion().WithKind("Gateway"), &unstructured.Unstructured{})
			scheme.AddKnownTypeWithName(gatewayGVR.GroupVersion().WithKind("GatewayList"), &unstructured.UnstructuredList{})
			dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
				gatewayGVR: "GatewayList",
			})
			if tt.object != nil {
				if _, err := dynamicClient.Resource(gatewayGVR).Namespace("test").Create(context.Background(), tt.object, metav1.CreateOptions{}); err != nil {
					t.Fatalf("create fake gateway: %v", err)
				}
			}
			client := &Client{dynamic: dynamicClient}

			got, err := client.GatewayUID(context.Background(), "test", "gateway")
			if got != tt.want {
				t.Errorf("GatewayUID() got = %q, want %q", got, tt.want)
			}
			if tt.wantErr == "" && err != nil {
				t.Errorf("GatewayUID() error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("GatewayUID() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestDeploymentRolledOut(t *testing.T) {
	two := int32(2)

	tests := []struct {
		name           string
		spec           *int32
		generation     int64
		observed       int64
		replicas       int32
		updated        int32
		available      int32
		progressReason string
		progressStatus corev1.ConditionStatus
		want           bool
		wantErr        bool
	}{
		{
			name: "complete", spec: &two,
			generation: 2, observed: 2, replicas: 2, updated: 2, available: 2,
			want: true,
		},
		{
			name: "progressing with new replica set available", spec: &two,
			generation: 2, observed: 2, replicas: 2, updated: 2, available: 2,
			progressReason: "NewReplicaSetAvailable", progressStatus: corev1.ConditionTrue,
			want: true, wantErr: false,
		},
		{
			name: "generation not observed", spec: &two,
			generation: 3, observed: 2, replicas: 2, updated: 2, available: 2,
			want: false,
		},
		{
			name: "surge pod mid-rollout", spec: &two,
			generation: 2, observed: 2, replicas: 3, updated: 1, available: 2,
			want: false,
		},
		{
			name: "old pod still counted", spec: &two,
			generation: 2, observed: 2, replicas: 3, updated: 2, available: 3,
			want: false,
		},
		{
			name: "updated pod not available", spec: &two,
			generation: 2, observed: 2, replicas: 2, updated: 2, available: 1,
			want: false,
		},
		{
			name: "nil spec replicas", spec: nil,
			generation: 1, observed: 1, replicas: 1, updated: 1, available: 1,
			want: true,
		},
		{
			name: "progress deadline exceeded", spec: &two,
			generation: 2, observed: 2, replicas: 2, updated: 1, available: 1,
			progressReason: "ProgressDeadlineExceeded", progressStatus: corev1.ConditionFalse,
			want: false, wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "link", Generation: tt.generation},
				Spec:       appsv1.DeploymentSpec{Replicas: tt.spec},
				Status: appsv1.DeploymentStatus{
					ObservedGeneration: tt.observed,
					Replicas:           tt.replicas,
					UpdatedReplicas:    tt.updated,
					AvailableReplicas:  tt.available,
				},
			}
			if tt.progressReason != "" {
				dep.Status.Conditions = append(dep.Status.Conditions, appsv1.DeploymentCondition{
					Type:   appsv1.DeploymentProgressing,
					Status: tt.progressStatus,
					Reason: tt.progressReason,
				})
			}

			got, err := deploymentRolledOut(dep)
			if got != tt.want {
				t.Errorf("deploymentRolledOut() got = %v, want %v", got, tt.want)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("deploymentRolledOut() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestXGatewayGCPStatusNames(t *testing.T) {
	tests := []struct {
		name    string
		object  *unstructured.Unstructured
		read    func(*Client) (string, error)
		want    string
		wantErr string
	}{
		{
			name:   "written template revision",
			object: xgatewayGCPObject(map[string]any{"templateRevision": "7f3a9c2d"}, map[string]any{}),
			read: func(c *Client) (string, error) {
				return c.GetXGatewayGCPTemplateRevision(context.Background(), "test", "gateway")
			},
			want: "7f3a9c2d",
		},
		{
			name:   "unwritten template revision",
			object: xgatewayGCPObject(map[string]any{}, map[string]any{"migName": "gw-abc-mig-4t1p"}),
			read: func(c *Client) (string, error) {
				return c.GetXGatewayGCPTemplateRevision(context.Background(), "test", "gateway")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{dynamic: fakeXGatewayGCPClient(t, tt.object)}

			got, err := tt.read(client)
			if got != tt.want {
				t.Errorf("status name = %q, want %q", got, tt.want)
			}
			if tt.wantErr == "" && err != nil {
				t.Errorf("status name error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("status name error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestWaitXGatewayGCPNames(t *testing.T) {
	tests := []struct {
		name    string
		spec    map[string]any
		status  map[string]any
		wait    func(*Client) (string, error)
		want    string
		wantErr string
	}{
		{
			name:   "mig name unpublished times out",
			status: map[string]any{},
			wait: func(c *Client) (string, error) {
				return c.WaitXGatewayGCPMIGName(context.Background(), "test", "gateway", time.Millisecond)
			},
			wantErr: "wait xgatewaygcp test/gateway status.migName",
		},
		{
			name: "template revision changed",
			spec: map[string]any{"templateRevision": "b1c4e6f8"},
			wait: func(c *Client) (string, error) {
				return c.WaitXGatewayGCPTemplateRevisionChanges(context.Background(), "test", "gateway", "7f3a9c2d", time.Millisecond)
			},
			want: "b1c4e6f8",
		},
		{
			name: "template revision unchanged times out",
			spec: map[string]any{"templateRevision": "7f3a9c2d"},
			wait: func(c *Client) (string, error) {
				return c.WaitXGatewayGCPTemplateRevisionChanges(context.Background(), "test", "gateway", "7f3a9c2d", time.Millisecond)
			},
			wantErr: "wait xgatewaygcp test/gateway spec.templateRevision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.spec
			if spec == nil {
				spec = map[string]any{}
			}
			status := tt.status
			if status == nil {
				status = map[string]any{}
			}
			client := &Client{dynamic: fakeXGatewayGCPClient(t, xgatewayGCPObject(spec, status))}

			got, err := tt.wait(client)
			if got != tt.want {
				t.Errorf("waited name = %q, want %q", got, tt.want)
			}
			if tt.wantErr == "" && err != nil {
				t.Errorf("waited name error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("waited name error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func xgatewayGCPObject(spec, status map[string]any) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{"spec": spec, "status": status}}
	obj.SetGroupVersionKind(xgatewayGCPGVR.GroupVersion().WithKind("XGatewayGCP"))
	obj.SetNamespace("test")
	obj.SetName("gateway")
	return obj
}

func fakeXGatewayGCPClient(t *testing.T, objects ...*unstructured.Unstructured) *fake.FakeDynamicClient {
	t.Helper()
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(xgatewayGCPGVR.GroupVersion().WithKind("XGatewayGCP"), &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(xgatewayGCPGVR.GroupVersion().WithKind("XGatewayGCPList"), &unstructured.UnstructuredList{})
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
		xgatewayGCPGVR: "XGatewayGCPList",
	})
	for _, obj := range objects {
		if obj == nil {
			continue
		}
		if _, err := dynamicClient.Resource(xgatewayGCPGVR).Namespace("test").Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
			t.Fatalf("create fake xgatewaygcp: %v", err)
		}
	}
	return dynamicClient
}

func TestGetGatewayCondition(t *testing.T) {
	gateway := func(generation int64, conditions []any) *unstructured.Unstructured {
		obj := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "wgnet.dev/v1alpha1",
			"kind":       "Gateway",
			"metadata": map[string]any{
				"name":      "gateway",
				"namespace": "test",
			},
			"status": map[string]any{"conditions": conditions},
		}}
		obj.SetGroupVersionKind(gatewayGVR.GroupVersion().WithKind("Gateway"))
		obj.SetNamespace("test")
		obj.SetName("gateway")
		obj.SetGeneration(generation)
		return obj
	}

	tests := []struct {
		name        string
		object      *unstructured.Unstructured
		wantStatus  string
		wantReason  string
		wantMessage string
		wantFound   bool
		wantErr     string
	}{
		{
			name: "condition from an older generation",
			object: gateway(2, []any{map[string]any{
				"type": "Ready", "status": "False", "reason": "Provisioning", "message": "waiting for link", "observedGeneration": int64(1),
			}}),
		},
		{
			name: "condition from the current generation",
			object: gateway(2, []any{map[string]any{
				"type": "Ready", "status": "False", "reason": "Provisioning", "message": "waiting for link", "observedGeneration": int64(2),
			}}),
			wantStatus: "False", wantReason: "Provisioning", wantMessage: "waiting for link", wantFound: true,
		},
		{
			name: "condition without generation",
			object: gateway(0, []any{map[string]any{
				"type": "Ready", "status": "False", "reason": "Provisioning", "message": "waiting for link",
			}}),
			wantStatus: "False", wantReason: "Provisioning", wantMessage: "waiting for link", wantFound: true,
		},
		{
			name: "condition absent",
			object: gateway(0, []any{map[string]any{
				"type": "Healthy", "status": "True", "reason": "Available", "message": "serving",
			}}),
		},
		{name: "gateway missing", wantErr: "get gateway test/gateway"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			scheme.AddKnownTypeWithName(gatewayGVR.GroupVersion().WithKind("Gateway"), &unstructured.Unstructured{})
			scheme.AddKnownTypeWithName(gatewayGVR.GroupVersion().WithKind("GatewayList"), &unstructured.UnstructuredList{})
			dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{
				gatewayGVR: "GatewayList",
			})
			if tt.object != nil {
				if _, err := dynamicClient.Resource(gatewayGVR).Namespace("test").Create(context.Background(), tt.object, metav1.CreateOptions{}); err != nil {
					t.Fatalf("create fake gateway: %v", err)
				}
			}
			client := &Client{dynamic: dynamicClient}

			status, reason, message, found, err := client.GetGatewayCondition(context.Background(), "test", "gateway", "Ready")
			if status != tt.wantStatus || reason != tt.wantReason || message != tt.wantMessage || found != tt.wantFound {
				t.Errorf("GetGatewayCondition() = (%q, %q, %q, %t), want (%q, %q, %q, %t)",
					status, reason, message, found, tt.wantStatus, tt.wantReason, tt.wantMessage, tt.wantFound)
			}
			if tt.wantErr == "" && err != nil {
				t.Errorf("GetGatewayCondition() error = %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("GetGatewayCondition() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}
