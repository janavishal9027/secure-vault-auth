#!/usr/bin/env bash
#
# Deploy the Authentication service to one of the secure-vault-* k3s clusters
# running inside an LXD container on the VPS.
#
# Architecture (mirrors the UI deploy):
#   1. Render manifests locally on the Bitbucket runner with sed.
#   2. scp rendered manifests + ci/deploy-remote.sh to the VPS.
#   3. ssh and run deploy-remote.sh as a regular file. Short SSH session
#      so flaky network paths can't kill long-lived heredocs.
#
# Required environment variables (set per environment in Bitbucket
# Deployment variables):
#   VPS_USER, VPS_HOST                SSH details for the LXD host
#   REMOTE_DIR                        Staging dir on the host for rendered
#                                     manifests (e.g. /root/secure-vault-dev-a/manifests)
#   LXD_CONTAINER                     LXD container name (e.g. secure-vault-dev-a)
#   KUBE_NAMESPACE                    k8s namespace inside the container
#   APP_NAME                          e.g. authentication
#   IMAGE_REPO                        Docker image repo (e.g. kittuvittu/secure-vault-authentication)
#   IMAGE_TAG                         Image tag — exported by the build step (commit SHA)
#   INGRESS_HOST                      Public hostname routed by host nginx
#   LXD_BRIDGE_IP                     IP of the LXD container on lxdbr0 — host nginx
#                                     proxy_pass target (e.g. 10.86.216.10)
#   DB_URL                            JDBC URL pointing at the LXD container's
#                                     bridge IP, e.g.
#                                     jdbc:postgresql://10.86.216.10:5432/digital-notes?currentSchema=secure-vault
#   DB_PASSWORD                       Postgres password
#   JWT_SECRET                        Base64-shaped HMAC secret — MUST match
#                                     the value used by notes, roles, and
#                                     ai-core-service so cross-service tokens
#                                     validate everywhere.
#   ROLES_SERVICE_URL                 Internal URL for the roles Feign client,
#                                     e.g. http://roles-service/roles
#   INTERNAL_ROLE_SERVICE_KEY         Shared secret between auth + roles
#   DELEGATE_BOOTSTRAP_KEY            First-admin bootstrap secret
#   OAUTH_GITHUB_CLIENT_ID            GitHub OAuth app credentials
#   OAUTH_GITHUB_CLIENT_SECRET
#   OAUTH_GOOGLE_CLIENT_ID            Google OAuth app credentials
#   OAUTH_GOOGLE_CLIENT_SECRET
#   MAIL_USERNAME                     SMTP sender (Gmail app account)
#   MAIL_PASSWORD                     Gmail app-password
#   FRONTEND_URL                      Public UI URL (used in OAuth + email links)
# Optional:
#   DB_USERNAME                       Default "postgres"
#   REPLICAS                          Default 1
#   JWT_EXPIRATION                    Default 1800000 (30 min, ms)
#   DELEGATE_BOOTSTRAP_ALLOW_FIRST_ONLY  Default "false"
#   MAIL_HOST                         Default smtp.gmail.com
#   MAIL_PORT                         Default 587
#   SWAGGER_ENABLED                   Default "false" (flip to "true" for dev)

set -euo pipefail

: "${VPS_USER:?}"
: "${VPS_HOST:?}"
: "${REMOTE_DIR:?}"
: "${LXD_CONTAINER:?}"
: "${KUBE_NAMESPACE:?}"
: "${APP_NAME:?}"
: "${IMAGE_REPO:?}"
: "${IMAGE_TAG:?}"
: "${INGRESS_HOST:?}"
: "${LXD_BRIDGE_IP:?}"
: "${DB_URL:?}"
: "${DB_PASSWORD:?}"
: "${JWT_SECRET:?}"
: "${ROLES_SERVICE_URL:?}"
: "${INTERNAL_ROLE_SERVICE_KEY:?}"
: "${DELEGATE_BOOTSTRAP_KEY:?}"
: "${OAUTH_GITHUB_CLIENT_ID:?}"
: "${OAUTH_GITHUB_CLIENT_SECRET:?}"
: "${OAUTH_GOOGLE_CLIENT_ID:?}"
: "${OAUTH_GOOGLE_CLIENT_SECRET:?}"
: "${MAIL_USERNAME:?}"
: "${MAIL_PASSWORD:?}"
: "${FRONTEND_URL:?}"

DB_USERNAME="${DB_USERNAME:-postgres}"
REPLICAS="${REPLICAS:-1}"
JWT_EXPIRATION="${JWT_EXPIRATION:-1800000}"
DELEGATE_BOOTSTRAP_ALLOW_FIRST_ONLY="${DELEGATE_BOOTSTRAP_ALLOW_FIRST_ONLY:-false}"
MAIL_HOST="${MAIL_HOST:-smtp.gmail.com}"
MAIL_PORT="${MAIL_PORT:-587}"
SWAGGER_ENABLED="${SWAGGER_ENABLED:-false}"

# Scope the staging dir per service. The input REMOTE_DIR is shared across
# microservices in the same namespace (e.g. /root/secure-vault-dev-a/manifests),
# so without this nesting concurrent deploys of different services would
# clobber each other's deploy-remote.sh and generic-named manifests.
REMOTE_DIR="${REMOTE_DIR}/${APP_NAME}"

REMOTE_TARGET="${VPS_USER}@${VPS_HOST}"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o BatchMode=yes
  -o ConnectTimeout=15
  -o ServerAliveInterval=30
  -o ServerAliveCountMax=10
)

# ---------------------------------------------------------------------------
# 1. Render manifests locally with sed.
#
# `|` delimiter so values containing `/` (image repos, JDBC urls) don't need
# escaping. Each substitution is its own `-e` clause so changes to one
# variable can't accidentally clobber another.
# ---------------------------------------------------------------------------
echo "==> Rendering manifests locally"
mkdir -p rendered
render_file() {
  local in="$1" out="$2"
  sed \
    -e "s|\${APP_NAME}|${APP_NAME}|g" \
    -e "s|\${KUBE_NAMESPACE}|${KUBE_NAMESPACE}|g" \
    -e "s|\${IMAGE_REPO}|${IMAGE_REPO}|g" \
    -e "s|\${IMAGE_TAG}|${IMAGE_TAG}|g" \
    -e "s|\${INGRESS_HOST}|${INGRESS_HOST}|g" \
    -e "s|\${REPLICAS}|${REPLICAS}|g" \
    -e "s|\${DB_URL}|${DB_URL}|g" \
    -e "s|\${DB_USERNAME}|${DB_USERNAME}|g" \
    -e "s|\${DB_PASSWORD}|${DB_PASSWORD}|g" \
    -e "s|\${JWT_SECRET}|${JWT_SECRET}|g" \
    -e "s|\${JWT_EXPIRATION}|${JWT_EXPIRATION}|g" \
    -e "s|\${ROLES_SERVICE_URL}|${ROLES_SERVICE_URL}|g" \
    -e "s|\${INTERNAL_ROLE_SERVICE_KEY}|${INTERNAL_ROLE_SERVICE_KEY}|g" \
    -e "s|\${DELEGATE_BOOTSTRAP_KEY}|${DELEGATE_BOOTSTRAP_KEY}|g" \
    -e "s|\${DELEGATE_BOOTSTRAP_ALLOW_FIRST_ONLY}|${DELEGATE_BOOTSTRAP_ALLOW_FIRST_ONLY}|g" \
    -e "s|\${OAUTH_GITHUB_CLIENT_ID}|${OAUTH_GITHUB_CLIENT_ID}|g" \
    -e "s|\${OAUTH_GITHUB_CLIENT_SECRET}|${OAUTH_GITHUB_CLIENT_SECRET}|g" \
    -e "s|\${OAUTH_GOOGLE_CLIENT_ID}|${OAUTH_GOOGLE_CLIENT_ID}|g" \
    -e "s|\${OAUTH_GOOGLE_CLIENT_SECRET}|${OAUTH_GOOGLE_CLIENT_SECRET}|g" \
    -e "s|\${MAIL_HOST}|${MAIL_HOST}|g" \
    -e "s|\${MAIL_PORT}|${MAIL_PORT}|g" \
    -e "s|\${MAIL_USERNAME}|${MAIL_USERNAME}|g" \
    -e "s|\${MAIL_PASSWORD}|${MAIL_PASSWORD}|g" \
    -e "s|\${FRONTEND_URL}|${FRONTEND_URL}|g" \
    -e "s|\${SWAGGER_ENABLED}|${SWAGGER_ENABLED}|g" \
    "$in" > "$out"
}
render_file deployment.yml rendered/deployment.yml
render_file service.yml    rendered/service.yml
render_file ingress.yml    rendered/ingress.yml

# nginx location snippet — separate sed pass since LXD_BRIDGE_IP isn't used by
# the k8s manifests, and conf files don't need any of the k8s-specific vars.
echo "==> Rendering nginx location snippet"
sed -e "s|\${LXD_BRIDGE_IP}|${LXD_BRIDGE_IP}|g" \
    ci/nginx/authentication.location.conf > rendered/authentication.location.conf

# Print rendered files with secrets redacted so they don't leak into pipeline
# logs. Bitbucket masks `Secured` variables in stdout already, but only the
# literal string — sed-rendered values can evade the mask. Cheap defense.
echo "=== Rendered manifests (secrets redacted) ==="
for f in rendered/*.yml; do
  echo "--- $f ---"
  sed \
    -e "s|${JWT_SECRET}|***JWT_SECRET***|g" \
    -e "s|${DB_PASSWORD}|***DB_PASSWORD***|g" \
    -e "s|${INTERNAL_ROLE_SERVICE_KEY}|***INTERNAL_ROLE_SERVICE_KEY***|g" \
    -e "s|${DELEGATE_BOOTSTRAP_KEY}|***DELEGATE_BOOTSTRAP_KEY***|g" \
    -e "s|${OAUTH_GITHUB_CLIENT_SECRET}|***OAUTH_GITHUB_CLIENT_SECRET***|g" \
    -e "s|${OAUTH_GOOGLE_CLIENT_SECRET}|***OAUTH_GOOGLE_CLIENT_SECRET***|g" \
    -e "s|${MAIL_PASSWORD}|***MAIL_PASSWORD***|g" \
    "$f"
done

# ---------------------------------------------------------------------------
# 2. Ship rendered manifests + the remote script to the VPS.
# ---------------------------------------------------------------------------
echo "==> Preparing remote staging dir ${REMOTE_DIR} on ${VPS_HOST}"
ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" "mkdir -p '${REMOTE_DIR}'"

echo "==> Shipping manifests + deploy-remote.sh to ${VPS_HOST}"
scp "${SSH_OPTS[@]}" \
    rendered/deployment.yml \
    rendered/service.yml \
    rendered/ingress.yml \
    rendered/authentication.location.conf \
    ci/deploy-remote.sh \
    "${REMOTE_TARGET}:${REMOTE_DIR}/"

# ---------------------------------------------------------------------------
# 3. Execute the remote script.
# ---------------------------------------------------------------------------
echo "==> Executing deploy-remote.sh on ${VPS_HOST}"
ssh "${SSH_OPTS[@]}" "$REMOTE_TARGET" \
    "env \
      APP_NAME='${APP_NAME}' \
      KUBE_NAMESPACE='${KUBE_NAMESPACE}' \
      IMAGE_REPO='${IMAGE_REPO}' \
      IMAGE_TAG='${IMAGE_TAG}' \
      INGRESS_HOST='${INGRESS_HOST}' \
      REPLICAS='${REPLICAS}' \
      REMOTE_DIR='${REMOTE_DIR}' \
      LXD_CONTAINER='${LXD_CONTAINER}' \
      LXD_BRIDGE_IP='${LXD_BRIDGE_IP}' \
      bash '${REMOTE_DIR}/deploy-remote.sh'"
