#!/usr/bin/env bash
# setup-gcp-project.sh — stand up a GCP project for running cyno e2e/deploy.
#
# Reads config from $REPO_ROOT/.env (see .env.example). Idempotent: every step
# checks current state before acting, so re-running is safe. Creates the
# project (optionally linking billing), enables the required APIs, and creates
# the provider-gcp service account with the roles cyno's Crossplane
# compositions need. Obtain credentials afterwards with get-gcp-creds.sh.

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

echo "Configuring GCP project '${GCP_PROJECT_ID}'..."

if gcloud projects describe "$GCP_PROJECT_ID" >/dev/null 2>&1; then
  echo "  project ${GCP_PROJECT_ID} already exists"
else
  echo "  creating project ${GCP_PROJECT_ID}"
  gcloud projects create "$GCP_PROJECT_ID"
fi

# Billing account is only needed when linking, so validate it lazily inside the branch.
if [[ "$(gcloud billing projects describe "$GCP_PROJECT_ID" \
      --format='value(billingEnabled)' 2>/dev/null)" == "True" ]]; then
  echo "  billing already enabled"
else
  require GCP_BILLING_ACCOUNT
  echo "  linking billing account ${GCP_BILLING_ACCOUNT}"
  gcloud billing projects link "$GCP_PROJECT_ID" \
    --billing-account="$GCP_BILLING_ACCOUNT"
fi

# APIs: enable is idempotent, so no pre-check needed.
echo "  enabling required APIs"
gcloud services enable \
  compute.googleapis.com \
  secretmanager.googleapis.com \
  iam.googleapis.com \
  cloudresourcemanager.googleapis.com \
  --project="$GCP_PROJECT_ID"

if gcloud iam service-accounts describe "$SA_EMAIL" \
    --project="$GCP_PROJECT_ID" >/dev/null 2>&1; then
  echo "  service account ${SA_EMAIL} already exists"
else
  echo "  creating service account ${SA_EMAIL}"
  gcloud iam service-accounts create "$CROSSPLANE_SA_NAME" \
    --project="$GCP_PROJECT_ID" \
    --display-name="cyno provider-gcp"
fi

# Roles: add-iam-policy-binding is idempotent, so loop unconditionally.
echo "  binding roles to ${SA_EMAIL}"
for role in \
  roles/compute.admin \
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
echo "Project ready."
echo "  Project:         ${GCP_PROJECT_ID}"
echo "  Service account: ${SA_EMAIL}"
echo "  Region / zone:   ${GCP_REGION:-unset} / ${GCP_ZONE:-unset}"
echo "  Next:            run scripts/get-gcp-creds.sh to obtain credentials"
