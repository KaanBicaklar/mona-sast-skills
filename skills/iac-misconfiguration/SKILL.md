---
name: iac-misconfiguration
description: >-
  SAST detection methodology for Infrastructure-as-Code misconfiguration
  (CWE-1188, CWE-732, CWE-16), covering public buckets, 0.0.0.0/0 security
  groups, wildcard IAM, unencrypted storage/RDS, IMDSv1, publicly exposed
  databases, disabled logging, and Kubernetes/Helm/Dockerfile issues (privileged
  containers, hostPath/hostNetwork, runAsRoot, missing NetworkPolicy, broad RBAC,
  plaintext secrets, root/latest images, baked secrets, ADD remote URLs). Use
  when reviewing *.tf, CloudFormation/k8s YAML, Dockerfile, or Helm charts. Writes
  confirmed findings to findings/36-iac-misconfiguration.md.
---

# Infrastructure-as-Code Misconfiguration — SAST Methodology

**Class:** IaC Misconfiguration · **CWE-1188 / CWE-732 / CWE-16** · **OWASP:** A05 Security Misconfiguration
**Findings file:** `findings/36-iac-misconfiguration.md`

## 1. Overview

Infrastructure-as-Code declares the cloud resources, network boundaries,
identities, and container runtime that everything else runs inside. A
misconfiguration here is a vulnerability *by declaration* — no tainted data flow
is needed, the insecure state is written literally in the config and deployed as
written. The dominant failure families: **exposure** (a resource reachable by the
public internet that shouldn't be — a public bucket, a security group open to
`0.0.0.0/0`, a database with a public IP), **excess privilege** (wildcard IAM,
over-broad RBAC, root/privileged containers), **missing protection** (no
encryption at rest, no logging/audit, IMDSv1 allowed), and **secret handling**
(plaintext secrets in env/manifests, secrets baked into image layers). The core
test for each resource: what can reach it, what can it do, is its data protected,
and does it run with least privilege?

## 2. Where it lives

- **Terraform:** `*.tf`, `*.tf.json`, modules, `*.tfvars` — `resource`, `data`,
  `provider`, and `variable`/`default` blocks; `terraform.tfstate` (may leak
  secrets).
- **CloudFormation / SAM / CDK synth:** `*.template`, `*.yaml`/`*.yml`,
  `*.json` under `Resources:`; CDK-generated templates.
- **Kubernetes:** `*.yaml`/`*.yml` manifests (`kind: Pod|Deployment|Service|
  Role|RoleBinding|NetworkPolicy|...`), Kustomize overlays.
- **Helm:** `templates/*.yaml`, `values.yaml` (defaults are what most users ship).
- **Dockerfile:** `Dockerfile`, `*.dockerfile`, `Containerfile`.
- **Other:** ARM/Bicep, Pulumi, Ansible playbooks, `docker-compose.yml`,
  serverless framework files — same categories, different syntax.

## 3. Sources (tainted input)

IaC is mostly *declarative misconfiguration*, so the "source" is the **declared
value itself** rather than a runtime taint. Still trace:

- **Variable/parameter defaults** and `*.tfvars`/`values.yaml` — an insecure
  default (`public = true`, `cidr = "0.0.0.0/0"`) ships to everyone who doesn't
  override it. The default is the effective source.
- **Module/chart inputs** wired from an untrusted or overly permissive caller,
  and **remote modules/charts** pulled from public registries (supply chain —
  cross-reference the dependency-and-supply-chain skill).
- **Interpolated build args / env** that inject secrets or attacker-influenced
  values into resources or images.
- **`ADD` with a remote URL** in a Dockerfile — network-fetched content becomes
  part of the image.

## 4. Sinks (dangerous operations)

```hcl
# Terraform — DANGEROUS: public bucket, world-open SSH, wildcard IAM, no encryption, IMDSv1
resource "aws_s3_bucket_public_access_block" "b" {
  block_public_acls = false            # public bucket exposure
  block_public_policy = false
}
resource "aws_security_group" "web" {
  ingress { from_port = 22  to_port = 22  protocol = "tcp"  cidr_blocks = ["0.0.0.0/0"] }  # SSH open to world
  ingress { from_port = 3306 to_port = 3306 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] } # DB open to world
}
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] }) # wildcard IAM
}
resource "aws_db_instance" "db" {
  storage_encrypted   = false          # unencrypted RDS
  publicly_accessible = true           # public database
}
resource "aws_instance" "i" {
  metadata_options { http_tokens = "optional" }   # IMDSv1 allowed → SSRF steals role creds
}
resource "aws_s3_bucket" "logs" {}      # no logging/versioning/access-logs configured
```
```yaml
# CloudFormation — DANGEROUS: wildcard principal / public S3 policy
Resources:
  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      PolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"                 # anyone
            Action: "s3:GetObject"
            Resource: "arn:aws:s3:::my-bucket/*"
```
```yaml
# Kubernetes — DANGEROUS: privileged, host namespaces, root, host mount, plaintext secret
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true                      # shares node network
  hostPID: true
  containers:
    - name: app
      image: myapp:latest                # mutable tag
      securityContext:
        privileged: true                 # full node capabilities → node/cluster takeover
        runAsNonRoot: false              # runs as root (uid 0)
        allowPrivilegeEscalation: true
      env:
        - name: DB_PASSWORD
          value: "S3cr3t!"               # plaintext secret in manifest
      volumeMounts:
        - { name: host, mountPath: /host }
  volumes:
    - name: host
      hostPath: { path: / }              # mounts host root FS
```
```yaml
# Kubernetes RBAC — DANGEROUS: cluster-admin-equivalent wildcard role
kind: ClusterRole
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]                         # can do anything, including read all secrets / escalate
# (and: no NetworkPolicy present → all pods can talk to all pods)
```
```dockerfile
# Dockerfile — DANGEROUS: root user, latest base, baked secret, remote ADD
FROM ubuntu:latest                       # mutable/unpinned base image
ADD https://example.com/install.sh /tmp/ # remote fetch into image, unverified
ARG AWS_SECRET_ACCESS_KEY                 # secret passed as build arg → persists in history/layers
ENV API_TOKEN=sk_live_abcdef123           # secret baked into a layer
COPY id_rsa /root/.ssh/id_rsa             # private key in image
# no USER directive → container runs as root
```

Dangerous patterns: public/anonymous access on storage; `0.0.0.0/0` (or `::/0`)
ingress on management/DB ports; `Action`/`Resource`/`Principal` wildcards; missing
encryption at rest; `publicly_accessible`/public IP on databases; IMDSv1
(`http_tokens = optional`); disabled logging/audit/flow-logs; k8s `privileged`,
`hostPath`/`hostNetwork`/`hostPID`, `runAsNonRoot: false`/`runAsUser: 0`, missing
`NetworkPolicy`, wildcard RBAC; plaintext secrets in env/manifests; Dockerfiles
running as root, using `latest`, baking secrets, or `ADD`-ing remote URLs.

## 5. Sanitizers / safe patterns

**Safe:**
- **Storage:** block all public access (`block_public_*  = true`), private ACLs,
  bucket policies scoped to specific principals, encryption at rest
  (`storage_encrypted = true`, SSE-KMS), versioning + access logging on.
- **Network:** ingress CIDRs scoped to known ranges; management ports (22/3389)
  and DB ports never `0.0.0.0/0` — front them with a bastion/SSM/VPN; databases
  in private subnets, `publicly_accessible = false`.
- **IAM/RBAC:** least privilege — explicit actions and resource ARNs, no `*`; no
  wildcard `Principal`; k8s Roles scoped to specific `apiGroups`/`resources`/
  `verbs` and namespaces; avoid `cluster-admin` bindings.
- **Instances:** IMDSv2 required (`http_tokens = "required"`), instance profiles
  least-privilege.
- **Kubernetes runtime:** `runAsNonRoot: true`, drop all capabilities,
  `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, no
  `privileged`/host namespaces/`hostPath`; default-deny `NetworkPolicy`; secrets
  via a `Secret`/external secret manager, not literal env values; enforce with
  Pod Security Admission / OPA-Gatekeeper / Kyverno.
- **Dockerfile:** pin base image by digest, add a non-root `USER`, use multi-stage
  builds and `--mount=type=secret` (never `ARG`/`ENV`/`COPY` for secrets), `COPY`
  local files instead of `ADD` remote URLs, `.dockerignore` credentials.
- **Logging:** enable CloudTrail/flow logs/audit logs and retention.

**Fails / not a real mitigation:**
- Encryption "enabled" with a default/shared key while the bucket/DB is still
  public — confidentiality already lost to anyone with access.
- A restrictive resource policy negated by a **separate** `0.0.0.0/0` security
  group or a public subnet route.
- k8s `runAsUser: 1000` at the pod level but a container overriding it, or
  `privileged: true` which **ignores** `runAsNonRoot` entirely.
- A `NetworkPolicy` that exists but selects no pods / has an empty ingress that
  actually **allows** all (semantics inverted).
- Dockerfile secret passed via `ARG` then "removed" in a later `RUN rm` — it
  persists in the earlier layer and image history.
- IMDSv2 "required" on the launch template but instances launched from a different
  AMI/config that allows v1.
- Wildcard IAM "scoped" by a permission boundary that isn't attached, or by a
  condition that is trivially satisfied.
- Secrets in a `Secret` object but stored unencrypted in etcd (no encryption
  provider), or checked into git in plaintext.

## 6. Detection methodology

1. **Inventory IaC files and resource types.**
   ```
   rg -l 'resource\s+"aws_|resource\s+"google_|resource\s+"azurerm_' -g '*.tf'
   rg -l 'AWSTemplateFormatVersion|Resources:' -g '*.template' -g '*.yaml' -g '*.yml'
   rg -l 'kind:\s*(Pod|Deployment|DaemonSet|StatefulSet|Role|ClusterRole|NetworkPolicy)' -g '*.yaml' -g '*.yml'
   rg -l '^FROM ' -g 'Dockerfile*' -g '*.dockerfile'
   ```
2. **Public exposure.**
   ```
   rg -n '0\.0\.0\.0/0|::/0' -g '*.tf' -g '*.yaml' -g '*.template'
   rg -n 'publicly_accessible\s*=\s*true|associate_public_ip_address\s*=\s*true' -g '*.tf'
   rg -n 'block_public_(acls|policy)\s*=\s*false|acl\s*=\s*"public-read' -g '*.tf'
   rg -n 'Principal:\s*["'\'']?\*' -g '*.yaml' -g '*.template'
   ```
3. **Wildcard IAM / RBAC.**
   ```
   rg -n '"Action":\s*"\*"|Action:\s*["'\'']?\*|"Resource":\s*"\*"|Resource:\s*["'\'']?\*' -g '*.tf' -g '*.yaml' -g '*.template'
   rg -n 'apiGroups:\s*\[?"?\*|resources:\s*\[?"?\*|verbs:\s*\[?"?\*' -g '*.yaml'
   ```
4. **Missing encryption / IMDSv1 / logging.**
   ```
   rg -n 'storage_encrypted\s*=\s*false|encrypted\s*=\s*false|http_tokens\s*=\s*"optional"' -g '*.tf'
   rg -n 'aws_s3_bucket\b' -g '*.tf'    # then verify each has SSE + logging + public-access-block
   ```
5. **Kubernetes runtime posture.**
   ```
   rg -n 'privileged:\s*true|hostNetwork:\s*true|hostPID:\s*true|hostPath:|runAsNonRoot:\s*false|runAsUser:\s*0|allowPrivilegeEscalation:\s*true' -g '*.yaml'
   rg -Ln 'kind:\s*NetworkPolicy' -g '*.yaml'    # absence across a namespace = finding
   rg -n 'kind:\s*Secret|stringData:|value:\s*.*(password|secret|token|key)' -g '*.yaml'
   ```
6. **Dockerfile hygiene.**
   ```
   rg -n 'FROM\s+\S+:latest|FROM\s+[^@]+$' Dockerfile*        # unpinned base
   rg -n '^ADD\s+https?://' Dockerfile*                        # remote ADD
   rg -n 'ARG\s+.*(SECRET|TOKEN|PASSWORD|KEY)|ENV\s+.*(SECRET|TOKEN|PASSWORD|KEY)=' Dockerfile*
   rg -Ln '^USER ' Dockerfile*                                 # no USER = runs as root
   ```
7. **Inspect variable/parameter defaults** (`variable {}` `default`, `Parameters:`
   `Default:`, `values.yaml`) — an insecure default is a live finding even if some
   callers override it.
8. **Confirm effective state:** a resource is only exposed if *every* layer agrees
   (SG + subnet route + resource policy). Read the whole path before concluding,
   and note whether the module is actually instantiated.

## 7. Modern & niche variants

- **Public buckets / blob containers:** `block_public_*` disabled, `acl =
  "public-read"`, wildcard `Principal`, or Azure `allow_blob_public_access`. The
  archetypal cloud data leak — public read of an entire object store.
- **Security groups open to `0.0.0.0/0`:** worst on management (SSH 22, RDP 3389)
  and database ports (3306/5432/6379/27017/1433/9200) — direct exposure of admin
  and data planes. IPv6 `::/0` is the same mistake and often missed.
- **Wildcard IAM (`Action:"*"`, `Resource:"*"`, `Principal:"*"`):** grants far more
  than needed; combined with any foothold it becomes privilege escalation to
  account admin. `iam:PassRole` + `*` and `sts:AssumeRole` on `*` are especially
  dangerous.
- **Unencrypted storage / volumes / RDS:** data at rest readable from snapshots,
  backups, or a stolen disk; often a compliance failure too. Includes EBS, RDS,
  S3 SSE off, k8s PVs, Kafka/Elasticsearch volumes.
- **IMDSv1 allowed (`http_tokens = optional`):** a server-side request forgery in
  any app on the instance can hit `169.254.169.254` and steal the instance role's
  credentials — the SSRF-to-cloud-takeover pivot. IMDSv2 (session tokens) blocks it.
- **Publicly exposed databases:** `publicly_accessible = true`, a public IP, or a
  `LoadBalancer`/NodePort service fronting a datastore — the DB is on the internet.
- **Disabled logging/audit:** no CloudTrail, VPC flow logs, S3 access logging,
  RDS/GKE audit logs — attacks become invisible and un-investigable; a
  detection-and-response gap that magnifies every other finding.
- **k8s privileged containers & host namespaces:** `privileged: true` grants all
  Linux capabilities and device access → trivial container escape to the node;
  `hostNetwork`/`hostPID`/`hostIPC` and `hostPath` mounts (especially `/`,
  `/var/run/docker.sock`) break the pod boundary directly.
- **`runAsRoot` / missing `securityContext`:** containers as uid 0 with default
  capabilities and no `readOnlyRootFilesystem`; a compromised process has far more
  power and a shorter path to escape.
- **Missing `NetworkPolicy`:** default Kubernetes networking is allow-all — any
  compromised pod can reach every service (lateral movement, metadata, internal
  APIs). Absence of a default-deny policy is itself the finding.
- **Over-broad RBAC:** wildcard `ClusterRole`s, `secrets` read across the cluster,
  `create`/`escalate`/`bind` on roles, `pods/exec`, or binding to
  `system:masters` — cluster-admin by another name.
- **Plaintext secrets as env:** literal passwords/tokens in `env value:`,
  `values.yaml`, Terraform `default`, or committed `.tfvars` — checked into git,
  in state, and in `describe` output.
- **Dockerfile: root, `latest`, baked secrets, remote `ADD`:** running as root
  widens escape impact; `:latest`/unpinned bases are non-reproducible and
  supply-chain-mutable; secrets via `ARG`/`ENV`/`COPY` persist in image history;
  `ADD https://...` pulls unverified network content into the image.

## 8. Common false positives

- A public bucket that is intentionally a static-website/CDN origin serving only
  non-sensitive public assets (confirm no private data and no write access).
- `0.0.0.0/0` on ports 80/443 for a genuine public web tier (still verify TLS,
  WAF, and that no admin/DB port shares the rule).
- Wildcard actions **scoped** by a resource ARN and a real, attached permission
  boundary / SCP / condition.
- k8s `NetworkPolicy` present as a default-deny with explicit allows, even if an
  individual pod manifest doesn't restate it.
- Dockerfile `latest` in a local dev-only stage or a base pinned by digest
  elsewhere; secrets provided via BuildKit `--mount=type=secret` (not persisted).
- Modules/resources defined but not instantiated (dead code) — note, don't rate as
  live.

## 9. Severity & exploitability

Base **High** for internet exposure and excess privilege; **Critical** when it
directly yields account/cluster takeover or crown-jewel data exposure — a public
bucket of sensitive data, `0.0.0.0/0` to a database or SSH, wildcard IAM usable to
reach admin, IMDSv1 that (with an app SSRF) leaks role creds, or a privileged/
host-namespace container enabling node/cluster escape. Raise for default-config
vulnerable and unauthenticated internet reachability; lower to **Medium/Low** for
missing logging alone, exposure limited to non-sensitive assets, or resources not
actually deployed. See `references/severity-model.md`.

## 10. Remediation

Block all public access and require encryption at rest on storage and databases;
keep databases private. Scope security-group ingress to known ranges and never
expose management/DB ports to `0.0.0.0/0`. Write least-privilege IAM/RBAC with
explicit actions and resource ARNs — no wildcards, no wildcard principals. Require
IMDSv2 and enable audit/flow/access logging. For Kubernetes: `runAsNonRoot`, drop
capabilities, no `privileged`/host namespaces/`hostPath`, default-deny
`NetworkPolicy`, secrets via a manager, enforced by Pod Security Admission/OPA/
Kyverno. For Dockerfiles: pin bases by digest, run as a non-root `USER`, keep
secrets out of layers (BuildKit secret mounts), prefer `COPY` over remote `ADD`.
Fix insecure variable defaults and gate merges with an IaC scanner (tfsec/Checkov/
KICS/Trivy).

## 11. Output

Append each confirmed finding to **`findings/36-iac-misconfiguration.md`** using
`references/finding-template.md`. Set `Class: IaC Misconfiguration` and `CWE:
CWE-1188` (insecure default), `CWE-732` (incorrect permission assignment), or
`CWE-16` (configuration) as fits. In **Chain potential** name primitives such as
*public network exposure* (→ an internet-reachable entry point other findings
consume), *cloud credential/role access* (via IMDSv1 or wildcard IAM → provides
creds that a chain uses to pivot), *privilege escalation to account/cluster admin*
(wildcard IAM/RBAC, privileged container → often terminal), *lateral movement*
(missing `NetworkPolicy`/host namespaces), and *secret disclosure* (plaintext/
baked secrets → feeds other chains). Note when it *consumes* a primitive such as
an app-layer SSRF (which turns IMDSv1 into credential theft) or a remote-module/
base-image supply-chain compromise.

**Primitives (controlled):** provides `CODE_EXEC`,`SECRET_LEAK`,`OUTBOUND_REQUEST`; consumes none

## References
- OWASP A05:2021 Security Misconfiguration; CWE-1188 (insecure default), CWE-732
  (incorrect permission assignment), CWE-16; CIS Benchmarks (AWS/Azure/GCP,
  Kubernetes, Docker); NSA/CISA Kubernetes Hardening Guide; AWS/GCP/Azure
  well-architected security pillars; tfsec/Checkov/KICS/Trivy rule sets.
