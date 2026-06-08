.PHONY: test test-unit test-integration test-e2e build clean lint lint-fix mocks helm-lint setup-gcp setup-gcp-sa gcp-creds docker-build crossplane-models generate manifests envtest

E2E_PARALLEL ?= 6

lint:
	gopls check -severity=hint $$(go list -f '{{range .GoFiles}}{{$$.Dir}}/{{.}}{{"\n"}}{{end}}' ./...)
	golangci-lint run ./...  --max-issues-per-linter 0 --max-same-issues 0 $(LINT_ARGS)

lint-fix:
	go fix ./...
	$(MAKE) lint LINT_ARGS="--fix $(LINT_ARGS)"

mocks:
	docker run -v "$(CURDIR)":/src -w /src docker.io/vektra/mockery:3

# Regenerate the typed XGatewayGCP spec/status views from the XRD's openAPIV3Schema.
crossplane-models:
	go run ./tools/xrdgen -xrd k8s/charts/wireguard-gateway-operator/crossplane/gcp/xgateway-xrd.yaml -out internal/crossplane/gcp

# Generate DeepCopy methods for API types.
generate:
	go tool controller-gen object paths=./pkg/api/...

# Generate CRD and RBAC manifests into the Helm chart.
manifests:
	go tool controller-gen crd rbac:roleName=gateway-operator paths=./pkg/api/... paths=./internal/controller/... output:crd:dir=k8s/charts/wireguard-gateway-operator/templates/crds output:rbac:dir=k8s/charts/wireguard-gateway-operator/templates

# Resolve the envtest binary path for the pinned k8s version. setup-envtest is
# pinned via the go.mod tool directive (tracking controller-runtime); the assets
# version is selected by ENVTEST_K8S_VERSION.
ENVTEST_K8S_VERSION ?= 1.35.x
envtest:
	@go tool setup-envtest use -p path $(ENVTEST_K8S_VERSION)

helm-lint:
	helm lint k8s/charts/wireguard-gateway-operator

# Stand up the GCP test project, create the provider-gcp service account, and
# obtain credentials. All read config from .env (see .env.example) and are
# idempotent.
setup-gcp:
	scripts/setup-gcp-project.sh

setup-gcp-sa:
	scripts/setup-gcp-sa.sh

gcp-creds:
	scripts/get-gcp-creds.sh

test: test-unit test-integration test-e2e

# Per-suite targets mirror the CI split: unit / integration / e2e run as
# independent jobs so a slow-suite failure does not mask the others. The timeout
# accommodates the controller package's envtest tests, each of which boots its own
# control plane, so the package's aggregate wall-clock under -race is far above a
# pure-unit budget.
test-unit:
	go test -race -timeout=180s -coverprofile=coverage.out $$(go list ./... | grep -vE '/test/(integration|e2e)(/|$$)')

test-integration:
	GATEWAY_INTEGRATION=1 go test -timeout 5m -count=1 ./test/integration/...

test-e2e:
	GATEWAY_E2E=1 go test -v -timeout 10m -parallel $(E2E_PARALLEL) -count=1 ./test/e2e/...

build:
	go build -o bin/gateway-link ./cmd/gateway-link
	go build -o bin/gateway-operator ./cmd/gateway-operator

# Build the runtime image holding the gateway-link binary. Override IMAGE to push
# a registry-qualified tag; defaults to a local gateway-link:dev.
IMAGE ?= gateway-link:dev
docker-build:
	docker build -f build/package/Dockerfile --target link -t $(IMAGE) .

# Build the operator image holding the gateway-operator binary. Override
# OPERATOR_IMAGE to push a registry-qualified tag.
OPERATOR_IMAGE ?= gateway-operator:dev
docker-build-operator:
	docker build -f build/package/Dockerfile --target operator -t $(OPERATOR_IMAGE) .

clean:
	go clean -testcache
	rm -f ./bin/*
