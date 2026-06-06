#!/usr/bin/env bash
# get-gcp-creds.sh — mint a GCP service-account key for the provider-gcp SA.
#
# Reads config from $REPO_ROOT/.env (see .env.example). Creates a key for the
# provider-gcp service account and writes it to the repo-relative, gitignored
# $GCP_CREDS_FILE. Loading the key into a cluster is NOT this script's job:
# the e2e harness does it for tests, and prod uses Workload Identity or a
# declarative secret mechanism. Run scripts/setup-gcp-project.sh first.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -f "$REPO_ROOT/.env" ]]; then
  echo "error: $REPO_ROOT/.env not found" >&2
  echo "       cp .env.example .env and fill it in" >&2
  exit 1
fi

# shellcheck disable=SC1091
set -a; source "$REPO_ROOT/.env"; set +a

require() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "error: $name is required; set it in $REPO_ROOT/.env" >&2
    exit 1
  fi
}

require GCP_PROJECT_ID
require CROSSPLANE_SA_NAME
require GCP_CREDS_FILE

SA_EMAIL="${CROSSPLANE_SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"
CREDS_PATH="$REPO_ROOT/$GCP_CREDS_FILE"

echo "Obtaining credentials for ${SA_EMAIL}..."

mkdir -p "$(dirname "$CREDS_PATH")"
gcloud iam service-accounts keys create "$CREDS_PATH" \
  --iam-account="$SA_EMAIL" \
  --project="$GCP_PROJECT_ID"
chmod 600 "$CREDS_PATH"

echo ""
echo "Credentials ready at ${GCP_CREDS_FILE}."
echo ""
echo "This file is the GCP-side credential. It is gitignored — never commit it."
echo ""
echo "Loading it into a cluster is intentionally not done here:"
echo "  - e2e tests: the e2e harness loads this key into the kind cluster as the"
echo "    ${CROSSPLANE_NAMESPACE}/${CROSSPLANE_CREDS_SECRET} Secret automatically."
echo "    You do not load it manually."
echo "  - prod: do NOT use this key path. The Crossplane ClusterProviderConfig"
echo "    defaults to InjectedIdentity (GKE Workload Identity, keyless). If you"
echo "    must supply a key, deliver it via your cluster's declarative secret"
echo "    mechanism (External Secrets Operator / SealedSecrets / GitOps)."
