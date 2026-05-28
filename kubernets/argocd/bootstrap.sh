#!/usr/bin/env bash
# Bootstrap ArgoCD on the AKS cluster and register the Argus AppProject
# + prod/dev ApplicationSets.
#
# Run once per cluster. Re-runs are idempotent (helm upgrade --install + kubectl apply).

set -euo pipefail

ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"
ARGOCD_CHART_VERSION="${ARGOCD_CHART_VERSION:-7.7.11}"   # argo-helm chart version
# Set to "true" when fronting argocd-server with NGINX Ingress (TLS terminated at the LB).
# Set to "false" for port-forward-only access (default).
ARGOCD_SERVER_INSECURE="${ARGOCD_SERVER_INSECURE:-false}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Ensuring namespace ${ARGOCD_NAMESPACE}"
kubectl get ns "${ARGOCD_NAMESPACE}" >/dev/null 2>&1 || \
  kubectl create ns "${ARGOCD_NAMESPACE}"

echo "==> Adding argo-helm repo"
helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1 || true
# Only refresh the argo repo — `helm repo update` (no args) fails the whole
# script if any *other* configured repo is unreachable (e.g. a stale local registry).
helm repo update argo >/dev/null

echo "==> Installing/upgrading ArgoCD (chart ${ARGOCD_CHART_VERSION})"
helm upgrade --install argocd argo/argo-cd \
  --namespace "${ARGOCD_NAMESPACE}" \
  --version "${ARGOCD_CHART_VERSION}" \
  --set configs.params."server\.insecure"=${ARGOCD_SERVER_INSECURE} \
  --set controller.metrics.enabled=true \
  --set repoServer.metrics.enabled=true \
  --set applicationSet.enabled=true \
  --wait --timeout=10m

echo "==> Waiting for ArgoCD rollouts"
kubectl -n "${ARGOCD_NAMESPACE}" rollout status deploy/argocd-server
kubectl -n "${ARGOCD_NAMESPACE}" rollout status deploy/argocd-repo-server
kubectl -n "${ARGOCD_NAMESPACE}" rollout status deploy/argocd-applicationset-controller

echo "==> Applying AppProject + ApplicationSets"
kubectl apply -n "${ARGOCD_NAMESPACE}" -f "${SCRIPT_DIR}/project.yaml"
kubectl apply -n "${ARGOCD_NAMESPACE}" -f "${SCRIPT_DIR}/appset-dev.yaml"
kubectl apply -n "${ARGOCD_NAMESPACE}" -f "${SCRIPT_DIR}/appset-prod.yaml"

echo
echo "Done."
echo
echo "Retrieve initial admin password:"
echo "  kubectl -n ${ARGOCD_NAMESPACE} get secret argocd-initial-admin-secret \\"
echo "    -o jsonpath='{.data.password}' | base64 -d && echo"
echo
echo "Port-forward UI:"
echo "  kubectl -n ${ARGOCD_NAMESPACE} port-forward svc/argocd-server 8080:443"
