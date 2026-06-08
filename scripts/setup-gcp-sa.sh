#!/usr/bin/env bash
# setup-gcp-sa.sh — create the provider-gcp service account and grant it the
# roles the gateway's Crossplane compositions need.
#
# Reads config from $REPO_ROOT/.env (see .env.example). Idempotent: re-running
# is safe. Run scripts/setup-gcp-project.sh first (the project and APIs must
# exist); obtain credentials afterwards with scripts/get-gcp-creds.sh.

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

SA_EMAIL="${CROSSPLANE_SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

echo "Configuring service account '${SA_EMAIL}'..."

if gcloud iam service-accounts describe "$SA_EMAIL" \
    --project="$GCP_PROJECT_ID" >/dev/null 2>&1; then
  echo "  service account ${SA_EMAIL} already exists"
else
  echo "  creating service account ${SA_EMAIL}"
  gcloud iam service-accounts create "$CROSSPLANE_SA_NAME" \
    --project="$GCP_PROJECT_ID" \
    --display-name="gateway provider-gcp"
fi

# Roles: add-iam-policy-binding is idempotent, so loop unconditionally.
echo "  binding roles to ${SA_EMAIL}"
for role in \
  roles/compute.instanceAdmin.v1 \
  roles/compute.networkAdmin \
  roles/compute.securityAdmin \
  roles/iam.serviceAccountAdmin \
  roles/iam.serviceAccountUser \
  roles/secretmanager.admin; do
  echo "    ${role}"
  gcloud projects add-iam-policy-binding "$GCP_PROJECT_ID" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="$role" \
    --condition=None \
    >/dev/null
done

echo ""
echo "Service account ready."
echo "  Service account: ${SA_EMAIL}"
echo "  Next:            run scripts/get-gcp-creds.sh to obtain credentials"
