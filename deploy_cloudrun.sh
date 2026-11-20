#!/usr/bin/env bash
# Deploy Kavach to Google Cloud Run (one command).
# Needs: gcloud installed + logged in (gcloud auth login) + a project with billing/credits.
# Usage:  ./deploy_cloudrun.sh            (uses current gcloud project)
#         PROJECT_ID=my-proj REGION=asia-south1 ./deploy_cloudrun.sh
set -euo pipefail
cd "$(dirname "$0")"

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-asia-south1}"          # Mumbai
SERVICE="${SERVICE:-kavach}"
if [ -z "$PROJECT_ID" ]; then echo "Set a project: gcloud config set project <PROJECT_ID>"; exit 1; fi
[ -f .env ] || { echo ".env not found. Copy .env.example to .env and add GEMINI_API_KEY."; exit 1; }

echo "== Project: $PROJECT_ID | Region: $REGION | Service: $SERVICE"
gcloud config set project "$PROJECT_ID" >/dev/null
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

# Turn .env into a Cloud Run env-vars file (empty values skipped). A random API key is
# generated for the admin/session endpoints if none is set, so the public URL is not open.
ENVFILE="$(mktemp)"
python3 - "$ENVFILE" <<'PY'
import os, sys, secrets
out = sys.argv[1]
vals = {}
for line in open(".env", encoding="utf-8"):
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    k = k.strip()
    # Never put a personal Gmail login on a public URL (set DEPLOY_GMAIL=1 to override)
    if k.startswith("GMAIL_") and os.getenv("DEPLOY_GMAIL") != "1":
        continue
    if v.strip():
        vals[k] = v.strip()
vals.setdefault("KAVACH_API_KEY", "kvc-" + secrets.token_urlsafe(18))
vals["KAVACH_DEPLOYMENT"] = "google-cloud-run"
with open(out, "w", encoding="utf-8") as f:
    for k, v in vals.items():
        f.write(f'{k}: "{v.replace(chr(34), chr(92) + chr(34))}"\n')
print("KAVACH_API_KEY for agents/skill:", vals["KAVACH_API_KEY"])
PY

# One instance keeps the live demo state (switch, runs, red team) in one place.
gcloud run deploy "$SERVICE" \
  --source . \
  --region "$REGION" \
  --allow-unauthenticated \
  --env-vars-file "$ENVFILE" \
  --min-instances 1 --max-instances 1 \
  --cpu 1 --memory 1Gi --no-cpu-throttling --timeout 300

rm -f "$ENVFILE"
URL="$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)')"
echo ""
echo "== Kavach is live on Google Cloud Run: $URL"
echo "   Dashboard:    $URL/"
echo "   Report:       $URL/trust-report"
echo "   For the Agent Skill: export KAVACH_URL=$URL"
