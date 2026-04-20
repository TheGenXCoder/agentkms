# AgentKMS Corp VPC Deployment Guide

AgentKMS is a secret-issuing authority for AI coding agents. It vends short-lived, scoped credentials — AWS STS session tokens, GitHub App PATs, Anthropic Admin API keys, and others — via an MCP interface. Agents get ephemeral credentials; the master credentials never leave AgentKMS. Every issuance is audited with full chain-of-custody forensics. The result: developer laptops hold no long-lived credentials at all. This guide walks an infosec or platform team through a production-grade Kubernetes deployment in a corporate VPC.

---

## Prerequisites

- **Kubernetes cluster** — EKS recommended for the AWS STS story (IRSA eliminates any static credentials on the node). GKE and self-hosted clusters work; see Step 1 for the workload identity variant.
- **kubectl** 1.27+ and **Helm** 3.12+ installed and pointed at the cluster.
- **AWS account** with IAM permissions sufficient to create roles and trust policies.
- **A domain** resolvable from developer laptops, e.g. `agentkms.internal.acmecorp.com`. Split-horizon DNS works; the endpoint does not need to be internet-accessible.
- **TLS certificates** — cert-manager is assumed in this guide. If you bring your own certs, skip the cert-manager stanzas in Step 2 and mount them manually.

---

## Architecture Overview

```
Developer laptop
  Claude Code / Cursor / kpm CLI
        │
        │  mTLS (client cert issued by corp CA)
        ▼
┌─────────────────────────────────────────┐
│           Corporate VPC                 │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │  AgentKMS (K8s pod)              │   │
│  │  - Policy engine                 │   │
│  │  - Audit log                     │   │
│  │  - Credential broker             │   │
│  └────────────┬─────────────────────┘   │
│               │ IAM role (IRSA / pod     │
│               │ identity) — no static   │
│               │ credentials on disk     │
└───────────────┼─────────────────────────┘
                │
      ┌─────────┴──────────────┐
      │                        │
      ▼                        ▼
 AWS STS                  GitHub App
 (AssumeRole)             (PAT vend)
      │
      ▼
 15-min session token
 returned to Claude Code
```

**What this achieves:**

- The AgentKMS pod authenticates to AWS via IRSA (no access key, no secret key stored anywhere).
- Developers authenticate to AgentKMS via mTLS client certificates. No passwords, no API keys in `~/.aws/credentials`.
- Credentials handed to Claude Code are scoped and expire automatically. If a session token leaks, it is useless within 15 minutes and the audit log shows exactly which agent requested it.

---

## Step 1: Create the IAM Role for AgentKMS

### EKS (IRSA)

**1a. Enable OIDC on your EKS cluster if not already done:**

```bash
eksctl utils associate-iam-oidc-provider \
  --cluster your-cluster-name \
  --region us-east-1 \
  --approve
```

**1b. Get the OIDC issuer URL:**

```bash
OIDC_URL=$(aws eks describe-cluster \
  --name your-cluster-name \
  --query "cluster.identity.oidc.issuer" \
  --output text)
# e.g. https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE
```

**1c. Create the trust policy** (`trust-policy.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub": "system:serviceaccount:agentkms:agentkms",
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
```

Replace the OIDC provider ID and account number with your values.

**1d. Create the role and attach the permissions policy:**

```bash
aws iam create-role \
  --role-name agentkms-prod \
  --assume-role-policy-document file://trust-policy.json

aws iam put-role-policy \
  --role-name agentkms-prod \
  --policy-name agentkms-credential-vend \
  --policy-document file://permissions-policy.json
```

`permissions-policy.json` — AgentKMS needs `sts:AssumeRole` on every role it will vend. Add `sts:GetCallerIdentity` for health checks:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VendCredentials",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::123456789012:role/staging-deploy",
        "arn:aws:iam::123456789012:role/staging-readonly",
        "arn:aws:iam::123456789012:role/prod-readonly"
      ]
    },
    {
      "Sid": "HealthCheck",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

Keep the `Resource` list tight. AgentKMS enforces policy on top of this, but IAM is the hard boundary.

### GKE (Workload Identity) — abbreviated

```bash
# Bind the K8s service account to a GCP service account
gcloud iam service-accounts add-iam-policy-binding \
  agentkms-prod@your-project.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:your-project.svc.id.goog[agentkms/agentkms]"
```

Then annotate the K8s service account (same annotation format as IRSA, just pointing at the GCP service account).

---

## Step 2: Deploy AgentKMS via Helm

**2a. Add the chart repo:**

```bash
helm repo add agentkms https://charts.catalyst9.ai
helm repo update
```

**2b. Create the namespace:**

```bash
kubectl create namespace agentkms
```

**2c. Write your values file** (`values.yaml`):

```yaml
replicaCount: 2

image:
  repository: ghcr.io/thegenxcoder/agentkms
  tag: v0.3.0
  pullPolicy: IfNotPresent

serviceAccount:
  create: true
  name: agentkms
  annotations:
    # IRSA — replace with your role ARN
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/agentkms-prod

tls:
  enabled: true
  certManager: true
  domain: agentkms.internal.acmecorp.com
  # mTLS — CA bundle for verifying client certs
  clientCA:
    secretName: agentkms-client-ca  # created in Step 3

audit:
  sink: stdout       # stdout feeds your log aggregator (Datadog, Splunk, etc.)
  # sink: file       # alternative: write to /var/log/agentkms/audit.log
  retention: 720h    # OSS default is 24h; 30 days shown here

policy:
  path: /etc/agentkms/policy.yaml
  configMapName: agentkms-policy   # created in Step 4

resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi

service:
  type: ClusterIP
  port: 8443

ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"   # preserve mTLS end-to-end
  hosts:
    - host: agentkms.internal.acmecorp.com
      paths:
        - path: /
          pathType: Prefix
```

**2d. Install:**

```bash
helm install agentkms agentkms/agentkms \
  -f values.yaml \
  -n agentkms \
  --wait
```

**2e. Verify the pod is running and the IRSA annotation took effect:**

```bash
kubectl get pods -n agentkms
kubectl exec -n agentkms deploy/agentkms -- \
  aws sts get-caller-identity
# Should return the agentkms-prod role ARN, not an EC2 instance role
```

---

## Step 3: Configure the PKI (mTLS)

AgentKMS uses mTLS to authenticate callers. The CN in the client certificate becomes the identity principal evaluated in policy rules. This is the only authentication mechanism — there are no passwords or bearer tokens.

### Option A: cert-manager (recommended)

**3a. Create a CA issuer in the `agentkms` namespace:**

```yaml
# ca-issuer.yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: agentkms-ca-issuer
  namespace: agentkms
spec:
  ca:
    secretName: agentkms-ca-secret
```

If you are using your existing corp CA, create the `agentkms-ca-secret` by importing your CA cert and key:

```bash
kubectl create secret tls agentkms-ca-secret \
  --cert=corp-ca.crt \
  --key=corp-ca.key \
  -n agentkms
```

**3b. Create the CA bundle ConfigMap for client cert verification:**

```bash
kubectl create secret generic agentkms-client-ca \
  --from-file=ca.crt=corp-ca.crt \
  -n agentkms
```

This matches `tls.clientCA.secretName` in your `values.yaml`.

**3c. Issue a developer client certificate using cert-manager:**

```yaml
# developer-cert.yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: alice-developer-cert
  namespace: agentkms
spec:
  secretName: alice-developer-cert-tls
  duration: 2160h    # 90 days
  renewBefore: 168h  # renew 7 days before expiry
  subject:
    organizations:
      - platform-team
  commonName: alice
  isCA: false
  usages:
    - client auth
  issuerRef:
    name: agentkms-ca-issuer
    kind: Issuer
```

Extract the cert and key for the developer:

```bash
kubectl get secret alice-developer-cert-tls -n agentkms \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > alice.crt
kubectl get secret alice-developer-cert-tls -n agentkms \
  -o jsonpath='{.data.tls\.key}' | base64 -d > alice.key
```

### Option B: openssl (no cert-manager)

```bash
# Generate CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key \
  -subj "/CN=AgentKMS Corp CA/O=acmecorp" \
  -out ca.crt

# Issue developer cert (CN = identity principal in policy)
openssl genrsa -out alice.key 2048
openssl req -new -key alice.key \
  -subj "/CN=alice/O=platform-team" \
  -out alice.csr
openssl x509 -req -days 90 \
  -in alice.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out alice.crt

# Mount CA for pod verification
kubectl create secret generic agentkms-client-ca \
  --from-file=ca.crt=ca.crt \
  -n agentkms
```

---

## Step 4: Write the Policy

AgentKMS evaluates a YAML policy before vending any credential. The policy lives in a ConfigMap and is hot-reloaded on SIGHUP (no pod restart required for policy changes).

**4a. Create the policy file** (`policy.yaml`):

```yaml
version: "1"

rules:
  # Developers on any team can vend scoped GitHub PATs for acmecorp repos
  - id: allow-github-for-developers
    effect: allow
    match:
      identity:
        # O= field from the client cert
        roles: [platform-team, backend-team, frontend-team]
      operations: [credential_vend]
    bounds:
      kind: github-pat
      max_params:
        repositories: ["acmecorp/*"]
      max_ttl: 1h

  # Developers can vend short-lived staging credentials
  - id: allow-aws-staging
    effect: allow
    match:
      identity:
        roles: [platform-team, backend-team]
      operations: [credential_vend]
    bounds:
      kind: aws-sts
      max_params:
        role_arn: ["arn:aws:iam::123456789012:role/staging-deploy"]
      max_ttl: 15m

  # Read-only prod access for on-call
  - id: allow-aws-prod-readonly
    effect: allow
    match:
      identity:
        # CN= field from the client cert (individual identity)
        subjects: [alice, bob]
      operations: [credential_vend]
    bounds:
      kind: aws-sts
      max_params:
        role_arn: ["arn:aws:iam::123456789012:role/prod-readonly"]
      max_ttl: 15m

  # Deny everything else — explicit default deny is good practice
  - id: default-deny
    effect: deny
    match:
      operations: ["*"]
```

Policy evaluation is first-match. Place more specific rules before broader ones. The `roles` field maps to the `O=` (Organization) field in the client cert; `subjects` maps to `CN=`.

**4b. Load the policy into a ConfigMap:**

```bash
kubectl create configmap agentkms-policy \
  --from-file=policy.yaml=policy.yaml \
  -n agentkms
```

**4c. Apply a policy change without restarting pods:**

```bash
# Edit the ConfigMap
kubectl edit configmap agentkms-policy -n agentkms

# Send SIGHUP to reload
kubectl exec -n agentkms deploy/agentkms -- \
  kill -HUP 1
```

---

## Step 5: Configure Developer Laptops

Distribute the client cert, key, and CA cert to each developer out-of-band (e.g. via your secrets manager or a secure internal portal). Then:

**5a. Install kpm:**

```bash
curl -sL kpm.catalyst9.ai/install | bash
```

**5b. Configure kpm** (`~/.kpm/config.yaml`):

```yaml
server: https://agentkms.internal.acmecorp.com:8443
cert: ~/.kpm/certs/client.crt
key: ~/.kpm/certs/client.key
ca: ~/.kpm/certs/ca.crt
```

Place the cert files at the paths shown, or adjust the config to match where you've put them.

**5c. Verify connectivity:**

```bash
kpm list
# Expected output:
# Available credential paths:
#   aws-sts/staging-deploy    (max TTL: 15m)
#   github-pat/acmecorp       (max TTL: 1h)
```

If you see paths, the mTLS handshake succeeded and your identity was matched to policy rules.

**5d. Add the MCP server to Claude Code:**

Edit `~/.claude/settings.json` (or the equivalent for your AI tool):

```json
{
  "mcpServers": {
    "agentkms": {
      "command": "agentkms-mcp"
    }
  }
}
```

`agentkms-mcp` is a small sidecar binary installed alongside kpm. It speaks the MCP protocol to Claude Code and delegates all credential requests to the kpm agent, which in turn calls the corp AgentKMS endpoint using the developer's client cert.

Claude Code will now show `agentkms` as an available MCP tool. No AWS credentials in `~/.aws/credentials`. No GitHub tokens in `.env` files.

---

## Step 6: Verify the Flow End-to-End

Run a real deployment and trace the credential lifecycle:

```bash
# Developer kicks off a deployment via Claude Code
kpm run -- claude "deploy the backend service to staging"
```

What happens internally:

1. Claude Code decides it needs AWS credentials and calls the `credential_vend` MCP tool.
2. `agentkms-mcp` forwards the request to AgentKMS over the mTLS connection.
3. AgentKMS evaluates the policy: identity `alice` (from cert CN), role `platform-team` (from cert O), operation `credential_vend`, kind `aws-sts`, role ARN `staging-deploy`.
4. Policy rule `allow-aws-staging` matches. AgentKMS calls `sts:AssumeRole` using the IRSA pod identity.
5. AWS returns a 15-minute session token. AgentKMS logs the issuance and returns the token to Claude Code.
6. Claude runs the deployment using the ephemeral token.
7. The token expires automatically after 15 minutes.

**Inspect the audit trail:**

```bash
# Live tail
akms audit tail

# Inspect a specific issuance by request ID
akms forensics inspect --request-id req_01j9xyz

# Example output:
# Request ID:   req_01j9xyz
# Timestamp:    2026-04-16T14:23:01Z
# Principal:    alice (CN) / platform-team (O)
# Operation:    credential_vend
# Kind:         aws-sts
# Role ARN:     arn:aws:iam::123456789012:role/staging-deploy
# TTL:          15m
# Policy Rule:  allow-aws-staging (allow)
# STS Request:  arn:aws:sts::123456789012:assumed-role/staging-deploy/agentkms-req_01j9xyz
# Outcome:      issued
```

Every issuance carries the full chain of custody: who requested it, which policy rule authorized it, which STS call was made, and what credential was returned.

---

## Operational Notes

### Scaling

AgentKMS is stateless for credential vending. Scale horizontally by increasing `replicaCount`. The audit sink is the only stateful concern:

- **`sink: stdout`** — recommended for production. Each pod writes JSON audit events to stdout; your log aggregator (Datadog, Splunk, OpenSearch) collects and indexes them. No shared state between replicas.
- **`sink: file`** — useful for development or airgapped environments. Writes to `/var/log/agentkms/audit.log`. If you use this with multiple replicas you need a shared volume or external log shipper per pod.

### Monitoring

```
GET /healthz    → 200 OK when pod is ready to serve
GET /metrics    → Prometheus metrics (credential_vend_total, policy_eval_duration_seconds, sts_call_duration_seconds, etc.)
```

Add a ServiceMonitor if you run the Prometheus Operator:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: agentkms
  namespace: agentkms
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: agentkms
  endpoints:
    - port: metrics
      interval: 30s
```

### Certificate Rotation

Client certs issued with a 90-day TTL (as shown in Step 3) are the recommended default. cert-manager handles renewal automatically before the `renewBefore` window. AgentKMS picks up changes to the CA bundle secret on SIGHUP — you do not need to restart pods when rotating the CA.

For CA rotation (adding a new CA while the old one is still valid):

```bash
# Build a bundle with both old and new CA certs
cat old-ca.crt new-ca.crt > bundle.crt
kubectl create secret generic agentkms-client-ca \
  --from-file=ca.crt=bundle.crt \
  -n agentkms --dry-run=client -o yaml | kubectl apply -f -
kubectl exec -n agentkms deploy/agentkms -- kill -HUP 1
# Now issue new developer certs signed by new CA
# Once all developers have new certs, remove old CA from bundle and SIGHUP again
```

### Disaster Recovery

The critical asset is the audit log. Everything else is reproducible from git.

| Asset | Where to store | How to restore |
|---|---|---|
| Audit logs | S3 or GCS (ship from log aggregator) | Replay from object storage |
| Policy YAML | Git | `kubectl apply` from repo |
| Helm values | Git | `helm upgrade` from repo |
| Client CA key | HSM or Vault (offline) | Re-issue from stored CA |
| IRSA role | Terraform / IaC | `terraform apply` |

The binary and Helm chart are pinned by image tag and chart version. A full cluster rebuild from a destroyed state is: restore IaC → `helm install` → SIGHUP. Audit history is intact in object storage.

### Upgrading

```bash
helm repo update
helm upgrade agentkms agentkms/agentkms \
  -f values.yaml \
  -n agentkms
```

Rolling update by default — existing connections are drained before pods are replaced. The plugin API is versioned; plugins built against a minor version continue to work across minor upgrades. Check the release notes for breaking changes before major version bumps.

---

## Troubleshooting

**`mTLS handshake failed` / `certificate verify failed`**

The CA bundle mounted in the AgentKMS pod does not include the CA that signed the developer's client cert.

```bash
# Check what CA the pod is using
kubectl exec -n agentkms deploy/agentkms -- \
  openssl verify -CAfile /etc/agentkms/client-ca/ca.crt /dev/stdin < alice.crt

# If it fails, the wrong CA bundle is mounted
kubectl describe secret agentkms-client-ca -n agentkms
```

Rebuild the bundle with the correct CA cert, update the secret, and send SIGHUP.

---

**`policy denied` when you expect allow**

```bash
# Tail audit log to see the denial reason and which rule fired
akms audit tail --filter outcome=denied

# Example output:
# policy_rule=default-deny reason="no allow rule matched"
# identity.subject=alice identity.roles=[frontend-team]
# operation=credential_vend kind=aws-sts role_arn=staging-deploy
```

The most common causes:

- The `O=` field in the developer cert does not match any `roles` entry in the allow rule.
- The requested role ARN is not in the `max_params.role_arn` list.
- The requested TTL exceeds `max_ttl`.

Print the cert to verify its subject fields:

```bash
openssl x509 -in alice.crt -noout -subject
# subject=CN=alice, O=frontend-team
```

---

**`STS AssumeRole failed` / `AccessDenied`**

```bash
# Verify the pod is actually using the IRSA role
kubectl exec -n agentkms deploy/agentkms -- \
  aws sts get-caller-identity
# Should return agentkms-prod role. If it returns the node's EC2 role,
# the IRSA annotation is missing or the OIDC provider is not associated.

# Verify the IRSA annotation is present
kubectl get serviceaccount agentkms -n agentkms -o yaml | grep role-arn
```

If the role ARN is correct but AssumeRole still fails, check the `Resource` list in the `agentkms-prod` permissions policy. The target role ARN must be explicitly listed. Also verify the target role's trust policy allows `agentkms-prod` to assume it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/agentkms-prod"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

---

**`kpm list` returns empty or connection refused**

```bash
# Check ingress is routing to the service
kubectl get ingress -n agentkms
kubectl get svc -n agentkms

# Test TLS directly (bypasses kpm to isolate the problem)
openssl s_client \
  -connect agentkms.internal.acmecorp.com:8443 \
  -cert alice.crt -key alice.key \
  -CAfile ca.crt \
  -verify_return_error
```

If `ssl-passthrough` is not enabled on your ingress, the ingress controller terminates TLS and AgentKMS never sees the client cert. Confirm the annotation `nginx.ingress.kubernetes.io/ssl-passthrough: "true"` is present and the ingress class supports passthrough.
