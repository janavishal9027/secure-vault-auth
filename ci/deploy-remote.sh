#!/usr/bin/env bash
#
# Runs ON THE LXD HOST (the VPS), invoked by ci/deploy.sh via SSH after that
# script has scp'd both this file and the rendered manifests over.
#
# Required environment (passed via `ssh ... env VAR=val bash this-file`):
#   APP_NAME, KUBE_NAMESPACE, IMAGE_REPO, IMAGE_TAG, INGRESS_HOST, REPLICAS,
#   REMOTE_DIR, LXD_CONTAINER, LXD_BRIDGE_IP
#
# Host nginx parent server block expected at /etc/nginx/sites-available/<cluster>,
# enabled in /etc/nginx/sites-enabled/, with this line inside the server block:
#   include /etc/nginx/snippets/<cluster>/*.location.conf;
# That parent block is provisioned ONCE by hand on the VPS (or by terraform);
# this script only manages this service's snippet inside that include directory.

set -euxo pipefail

: "${APP_NAME:?}"
: "${KUBE_NAMESPACE:?}"
: "${IMAGE_REPO:?}"
: "${IMAGE_TAG:?}"
: "${INGRESS_HOST:?}"
: "${REMOTE_DIR:?}"
: "${LXD_CONTAINER:?}"
: "${LXD_BRIDGE_IP:?}"
REPLICAS="${REPLICAS:-1}"

# Snap binaries (lxc / lxd) live in /snap/bin, which non-interactive SSH
# does NOT pick up by default — without this we'd hit `lxc: command not found`.
export PATH="/snap/bin:$PATH"

# Tee everything to a log file on the host. Survives even if SSH dies.
mkdir -p "$REMOTE_DIR"
exec > >(tee -a "$REMOTE_DIR/deploy.log") 2>&1

echo "=== deploy-remote.sh starting at $(date -Iseconds) ==="
echo "    APP_NAME=$APP_NAME  LXD_CONTAINER=$LXD_CONTAINER  KUBE_NAMESPACE=$KUBE_NAMESPACE"
echo "    IMAGE=$IMAGE_REPO:$IMAGE_TAG  INGRESS_HOST=$INGRESS_HOST  REPLICAS=$REPLICAS"

cd "$REMOTE_DIR"

# `lxc exec` / `lxc file push` occasionally return `websocket: close 1006
# (abnormal closure)` when the lxd daemon's transport hiccups. The inner
# work is usually idempotent (kubectl apply, mkdir -p, file push), so a
# few retries bridge past flakes without losing the deploy.
lxc_retry() {
  local attempt=1
  local max_attempts=4
  local rc=0
  while [ "$attempt" -le "$max_attempts" ]; do
    if "$@"; then
      return 0
    fi
    rc=$?
    if [ "$attempt" -ge "$max_attempts" ]; then
      echo "  lxc operation failed after ${max_attempts} attempts (rc=${rc}): $*" >&2
      return $rc
    fi
    echo "  lxc operation failed (attempt ${attempt}/${max_attempts}, rc=${rc}); retrying in 2s..." >&2
    sleep 2
    attempt=$((attempt + 1))
  done
}

# Wait for k3s to be ready inside the container before invoking kubectl.
# Cloud-init can take ~60-90s the first time.
echo "=== Waiting for k3s to be ready in $LXD_CONTAINER (max 5 min) ==="
ATTEMPT=0
MAX_ATTEMPTS=60
until lxc exec "$LXD_CONTAINER" -- /usr/local/bin/k3s kubectl get nodes >/dev/null 2>&1; do
  ATTEMPT=$((ATTEMPT + 1))
  if [ "$ATTEMPT" -ge "$MAX_ATTEMPTS" ]; then
    echo "ERROR: k3s never came up in $LXD_CONTAINER after 5 minutes." >&2
    lxc_retry lxc exec "$LXD_CONTAINER" -- tail -n 80 /var/log/cloud-init-output.log >&2 || true
    exit 1
  fi
  echo "  attempt ${ATTEMPT}/${MAX_ATTEMPTS}: k3s API not yet responding, retrying in 5s..."
  sleep 5
done
echo "k3s is ready in $LXD_CONTAINER"

kubectl_in_container() {
  lxc_retry lxc exec "$LXD_CONTAINER" -- /usr/local/bin/k3s kubectl "$@"
}

echo "=== Cluster context ==="
kubectl_in_container get nodes -o wide
kubectl_in_container get ingressclass

echo "=== Namespace ==="
kubectl_in_container get namespace "$KUBE_NAMESPACE" >/dev/null 2>&1 \
  || kubectl_in_container create namespace "$KUBE_NAMESPACE"

echo "=== Pushing manifests into $LXD_CONTAINER ==="
lxc_retry lxc exec "$LXD_CONTAINER" -- mkdir -p "/tmp/manifests/${APP_NAME}"
for f in deployment.yml service.yml ingress.yml; do
  lxc_retry lxc file push "$f" "${LXD_CONTAINER}/tmp/manifests/${APP_NAME}/${f}"
  if ! lxc_retry lxc exec "$LXD_CONTAINER" -- test -s "/tmp/manifests/${APP_NAME}/${f}"; then
    echo "ERROR: /tmp/manifests/${APP_NAME}/${f} missing or empty inside container after push" >&2
    exit 1
  fi
done

echo "=== Applying manifests to namespace '$KUBE_NAMESPACE' ==="
for f in deployment.yml service.yml ingress.yml; do
  echo "--- applying $f ---"
  kubectl_in_container -n "$KUBE_NAMESPACE" apply -f "/tmp/manifests/${APP_NAME}/$f" -o name
done

echo "=== Post-apply existence check ==="
verify_resource() {
  local kind="$1" name="$2"
  if ! kubectl_in_container -n "$KUBE_NAMESPACE" get "$kind" "$name" >/dev/null 2>&1; then
    echo "ERROR: $kind/$name not found in namespace $KUBE_NAMESPACE after apply" >&2
    kubectl_in_container -n "$KUBE_NAMESPACE" get all,ingress -o wide >&2 || true
    exit 1
  fi
  kubectl_in_container -n "$KUBE_NAMESPACE" get "$kind" "$name"
}
verify_resource deployment "${APP_NAME}-deployment"
verify_resource service    "${APP_NAME}-service"
verify_resource ingress    "${APP_NAME}-ingress"

# Spring Boot cold-starts can take 30-90s (JVM + classpath scan + Hibernate
# schema validation). The readiness probe (initialDelaySeconds: 20) gates
# Available, so this wait is the source of truth for "the JVM is up and
# listening on 3211".
echo "=== Waiting for deployment to be Available (max 4 min) ==="
kubectl_in_container -n "$KUBE_NAMESPACE" \
  wait "deployment/${APP_NAME}-deployment" \
  --for=condition=Available --timeout=240s

echo "=== Service endpoints ==="
endpoints=$(kubectl_in_container -n "$KUBE_NAMESPACE" \
  get "endpoints/${APP_NAME}-service" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || true)
if [[ -z "$endpoints" ]]; then
  echo "ERROR: service ${APP_NAME}-service has no endpoints — pod not Ready or selector mismatch" >&2
  kubectl_in_container -n "$KUBE_NAMESPACE" describe "endpoints/${APP_NAME}-service" >&2 || true
  kubectl_in_container -n "$KUBE_NAMESPACE" get pods -o wide --show-labels >&2 || true
  exit 1
fi
echo "endpoints: $endpoints"

# Routing test: hit /authentication/login with a POST. We don't supply
# credentials, so the service responds with 400/401/415/422 — anything
# that came from Spring (not Traefik). Traefik's "no matching ingress"
# returns the literal "404 page not found" plain-text body; we accept
# ANY response whose body is not that exact string. Status-code matching
# isn't reliable here because auth endpoints intentionally don't return
# 2xx for unauthenticated probes.
echo "=== Routing test (Traefik forwards /authentication/* to the service?) ==="
body=$(lxc_retry lxc exec "$LXD_CONTAINER" -- curl -s --max-time 10 \
  -H "Host: $INGRESS_HOST" \
  -H "Content-Type: application/json" \
  -X POST -d '{}' \
  http://127.0.0.1/authentication/login || true)
status=$(lxc_retry lxc exec "$LXD_CONTAINER" -- curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
  -H "Host: $INGRESS_HOST" \
  -H "Content-Type: application/json" \
  -X POST -d '{}' \
  http://127.0.0.1/authentication/login || true)
echo "POST /authentication/login -> HTTP $status"
echo "body: ${body:-<empty>}"
if [[ "$body" == "404 page not found" ]]; then
  echo "ERROR: Traefik returned its 404 page — ingress not registered for $INGRESS_HOST/authentication" >&2
  kubectl_in_container -n "$KUBE_NAMESPACE" describe "ingress/${APP_NAME}-ingress" >&2 || true
  kubectl_in_container -n kube-system logs -l app.kubernetes.io/name=traefik --tail=40 >&2 || true
  exit 1
fi
echo "OK: response came from Authentication (not Traefik 404)"

# ---------------------------------------------------------------------------
# Install host nginx location snippet.
#
# Parent server block at /etc/nginx/sites-available/<cluster> does
#   include /etc/nginx/snippets/<cluster>/*.location.conf;
# so all we do here is drop our snippet into that directory and reload nginx.
# `nginx -t` validates the WHOLE nginx config — if our snippet is broken,
# we exit before reload, leaving the previously-working config in place.
# ---------------------------------------------------------------------------
echo "=== Installing nginx location snippet for $APP_NAME ==="
SNIPPET_DIR="/etc/nginx/snippets/${KUBE_NAMESPACE}"
SNIPPET_DST="${SNIPPET_DIR}/${APP_NAME}.location.conf"
mkdir -p "$SNIPPET_DIR"
cp "$REMOTE_DIR/authentication.location.conf" "$SNIPPET_DST"
echo "Installed snippet at $SNIPPET_DST"

echo "=== nginx -t (config validation) ==="
nginx -t

echo "=== Reloading nginx ==="
systemctl reload nginx
echo "nginx reloaded"

echo "=== Final namespace state ==="
kubectl_in_container -n "$KUBE_NAMESPACE" get all,ingress -o wide
echo "=== Deploy complete: $APP_NAME -> $LXD_CONTAINER/$KUBE_NAMESPACE @ $IMAGE_REPO:$IMAGE_TAG ==="
echo "=== deploy-remote.sh finished at $(date -Iseconds) ==="
