# Multi-Layered Security Monitoring for Kubernetes and Containers with Open Source Tools

> **Bachelor's Thesis: Proof of Concept and evidence repository**
> A four-layer security monitoring stack for Kubernetes, built only from open source tools and evaluated against [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat), a deliberately vulnerable target. Every claim in the thesis can be traced to a file in this repository.

---

## Table of Contents

- [Overview](#overview)
- [Threat Model](#threat-model)
- [Architecture](#architecture)
- [Security Layers](#security-layers)
- [Attack Scenarios & Detection](#attack-scenarios--detection)
- [Stack Components](#stack-components)
- [Installation Guide](#installation-guide)
- [Dashboard Access](#dashboard-access)
- [Repository Structure](#repository-structure)
- [Key Technical Decisions](#key-technical-decisions)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Lessons Learned](#lessons-learned)
- [Real-World Threat Context](#real-world-threat-context)
- [References](#references)

---

## Overview

The stack covers four points in a workload's lifecycle: pre-runtime image scanning (Trivy Operator), admission-time policy enforcement (Kyverno), network-layer mutual TLS (Istio + Kiali), and runtime syscall detection (Falco + Falcosidekick). Prometheus, Grafana and Loki form the observability spine underneath all four.

The argument is that **no single tool is sufficient**, because each layer observes a different, structurally bounded part of the lifecycle. The evaluation shows the coverage is complementary rather than redundant: fileless execution from `/dev/shm` is invisible to scanning, admission and the mesh and is caught only by Falco, while pods that request host namespaces or run as root are refused at admission, which none of the other layers can do.

The full installation reference is in [`PoC.txt`](PoC.txt). Evidence for each layer (screenshots, reports, alert output) lives in that layer's directory. The defence presentation is in [`Multi-Layered_Security_Monitoring_for_Kubernetes_and_Containers_with_Open_Source_Tools.pdf`](Multi-Layered_Security_Monitoring_for_Kubernetes_and_Containers_with_Open_Source_Tools.pdf).

---

## Threat Model

The adversary has already obtained code execution inside one container (the `health-check` pod in the `default` namespace). Initial access is not modelled. From that foothold the adversary harvests credentials, evades file-based detection, contacts external infrastructure and probes the Kubernetes API.

Each layer is classified by what it can do against that adversary:

| Layer | Semantics | What it does |
|---|---|---|
| Trivy Operator | Monitoring | Reports the CVE burden of every running image |
| Kyverno | Prevention | Refuses non-compliant pods before they exist |
| Istio (mTLS STRICT) | Enforcement | Rejects connections without a valid mesh identity |
| Falco | Monitoring | Observes every syscall; alerts, does not block |

---

## Architecture

```
Kubernetes Cluster (kind v0.26.0 / Kubernetes v1.32.0, single node)
│
├── Kubernetes Goat (attack target)
│   ├── namespace: default             ← health-check (attack target), kubernetes-goat-home,
│   │                                     metadata-db, internal-api, poor-registry, system-monitor
│   ├── namespace: big-monolith        ← hunger-check (admission-control evidence)
│   └── namespace: secure-middleware   ← cache-store
│
├── namespace: falco          ← Falco DaemonSet (modern_ebpf), Falcosidekick, Falcosidekick UI
├── namespace: monitoring     ← Prometheus, Grafana, AlertManager, Loki
├── namespace: trivy-system   ← Trivy Operator
├── namespace: kyverno        ← Kyverno admission controller
└── namespace: istio-system   ← istiod, Kiali
```

---

## Security Layers

### Layer 1: Pre-runtime, Trivy Operator

Trivy Operator runs as a controller, scans every workload image on its own schedule and publishes `VulnerabilityReport` custom resources, queryable with `kubectl`. A vulnerability disclosed after deployment surfaces on the next scan cycle without operator action.

**Findings on Kubernetes Goat, before any attack (reports in [`trivy/`](trivy/)):**

| Image | Critical | High | Medium | Low |
|---|---|---|---|---|
| `k8s-goat-poor-registry` | 5 | 47 | 55 | 2 |
| `k8s-goat-internal-api` | 2 | 26 | 45 | 16 |
| `k8s-goat-home` | 2 | 10 | 23 | 7 |
| `k8s-goat-cache-store` | 0 | 4 | 26 | 4 |
| `k8s-goat-system-monitor` | 0 | 1 | 81 | 52 |
| **Total** | **9** | **88** | **230** | **81** |

The two critical findings in `k8s-goat-home` are one OpenSSL vulnerability reported once per package (`libssl3` and `libcrypto3`):
- `CVE-2025-15467`: stack buffer overflow in CMS (Auth)EnvelopedData parsing via an oversized IV (possible remote code execution)

Every Alpine-based image is additionally flagged with an end-of-support base.

Evidence: [`trivy/trivy-vulnerability-reports-all-namespaces.png`](trivy/trivy-vulnerability-reports-all-namespaces.png), [`trivy/trivy-vulnerability-report-detail.png`](trivy/trivy-vulnerability-report-detail.png).

```bash
kubectl get vulnerabilityreports -A -o custom-columns=\
"NAMESPACE:.metadata.namespace,NAME:.metadata.name,\
CRITICAL:.report.summary.criticalCount,HIGH:.report.summary.highCount,\
MEDIUM:.report.summary.mediumCount,LOW:.report.summary.lowCount"
```

---

### Layer 2: Admission control, Kyverno

Kyverno registers as a validating admission webhook. In `Enforce` mode non-compliant pods are rejected before they are persisted. Five ClusterPolicies are applied from [`kyverno/policies/`](kyverno/policies/):

| Policy | Rejects |
|---|---|
| `block-privileged` | Containers with `privileged: true` |
| `require-non-root` | Containers without `runAsNonRoot` |
| `block-latest-tag` | Images referenced by `:latest` |
| `block-host-namespaces` | Pods using `hostNetwork`, `hostPID` or `hostIPC` |
| `require-resource-limits` | Containers without CPU and memory limits |

All five exclude the six infrastructure namespaces `falco`, `kube-system`, `monitoring`, `istio-system`, `trivy-system` and `kyverno`. The target namespaces are never excluded.

**Enforcement against an unmodified Kubernetes Goat workload:** `hunger-check-deployment` is exported, deleted and reapplied unchanged:

```
admission webhook "validate.kyverno.svc-fail" denied the request:
require-non-root: autogen-require-non-root failed at path
  /spec/template/spec/containers/0/securityContext/
require-resource-limits: autogen-require-limits failed at path
  /spec/template/spec/containers/0/resources/limits/
```

Three further isolated test pods (`test-nolimits`, `test-latest`, `test-hostnet`) exercise four of the five policies directly (thesis Section 5.2.2). `block-privileged` was not triggered by a dedicated test. The commands and outputs of all four tests are in [`kyverno/test.txt`](kyverno/test.txt).

Evidence: [`kyverno/kyverno-hunger-check.png`](kyverno/kyverno-hunger-check.png), [`kyverno/kyverno-test-hostnet-rejected.jpg`](kyverno/kyverno-test-hostnet-rejected.jpg), [`kyverno/kyverno-clusterpolicies-all-5-ready.png`](kyverno/kyverno-clusterpolicies-all-5-ready.png), [`kyverno/kyverno-policy-violation-events.png`](kyverno/kyverno-policy-violation-events.png).

---

### Layer 3: Network, Istio + Kiali

Istio 1.24.0 (`demo` profile) injects an Envoy sidecar into every pod in `default`, `big-monolith` and `secure-middleware`. A `PeerAuthentication` in `STRICT` mode is applied to each of the three namespaces ([`istio/mtls/peer-authentication.yaml`](istio/mtls/peer-authentication.yaml)), so a connection without a valid SPIFFE identity issued by `istiod` cannot complete the handshake.

**What Kiali shows:** traffic generated from `health-check` renders as `health-check → kubernetes-goat-home-service → kubernetes-goat-home`, with an mTLS padlock on each edge and a 100% success rate. A cross-namespace variant (from `hunger-check` to `metadata-db.default.svc.cluster.local`) was also run, but the captured graph does not show that edge, so no captured cross-namespace evidence is claimed. No scenario attempted a connection that STRICT mode would refuse. Enforcement is confirmed active, not observed blocking an attack.

Evidence: [`istio/kiali-traffic-graph-service-mesh.png`](istio/kiali-traffic-graph-service-mesh.png).

---

### Layer 4: Runtime, Falco + Prometheus + Grafana + Loki

Falco runs as a DaemonSet with the `modern_ebpf` driver (CO-RE/BTF: no kernel headers, no compilation, no init container). Falcosidekick fans each alert out to the Falcosidekick UI, Prometheus and Loki.

**Falco configuration ([`falco/helm-values.yaml`](falco/helm-values.yaml) + [`falco/custom-rules.yaml`](falco/custom-rules.yaml), passed in that order):**
- `helm-values.yaml`: driver, metrics, webserver, `http_output`, and the earlier narrowing attempt (`known_drop_and_execute_*` extensions).
- `custom-rules.yaml`: the `tuning.yaml` block that disables two community rules, and the two detection rules written for this thesis (`Read Kubernetes Service Account Token`, `Detect curl or wget inside container`). Because it is passed second and defines the same `customRules` key, it replaces the narrowing attempt. The deployed ruleset is the one in this file.

**Noise reduction:** the default ruleset fired continuously on kubelet mount operations, Prometheus scrapes and node-exporter reads. Narrowing the rules with exclusion lists was tried first and did not remove the noise. Two community rules were then disabled outright: `Drop and execute new binary in container` and `Redirect STDOUT/STDIN to Network Connection in Container`. This is a permanent, cluster-wide reduction in coverage. The attacked namespaces were never exempted from any rule.

**Tuning outcome:** after the two disables, kubelet, Prometheus and node-exporter activity produced zero alerts. Rule match counts (`falcosecurity_falco_rules_matches_total`, cumulative since the tuned Falco pod started):

| Rule | Matches | Attributable to |
|---|---|---|
| Read sensitive file untrusted | 3 | PoC 1 |
| Execution from /dev/shm | 3 | PoC 2 |
| Read Kubernetes Service Account Token | 2 | PoC 3 (custom rule) |
| Detect curl or wget inside container | 5 | PoC 4 (custom rule) |
| **Total** | **13** | |

The counts exceed one per scenario because scenarios were re-run during development. PoC 5 does not appear in these counters; its alert is evidenced separately. No false-positive rate is reported: the lab has no representative baseline of everyday traffic to compute one against.

**Measured cost (Prometheus, `falcosecurity_*` metrics):**

| Metric | Value |
|---|---|
| CPU | 5.5% of one core |
| Memory (RSS) | 158 MB |
| Syscall throughput | 8,823 events/s |
| Dropped events | 0 |

Evidence: [`grafana/`](grafana/), [`prometheus/`](prometheus/), [`loki/loki-falco-warning-logs-explore.png`](loki/loki-falco-warning-logs-explore.png).

---

## Attack Scenarios & Detection

All five scenarios run against the `health-check` pod in the `default` namespace, resolved by label, in a single session (container `d316001c9c96`). Full transcripts: [`falco/Attacks PoC.txt`](falco/Attacks%20PoC.txt).

```bash
kubectl exec -n default \
  $(kubectl get pod -n default -l app=health-check \
    -o jsonpath='{.items[0].metadata.name}') \
  -- sh -c "<attack command>"
```

Where the thesis technique differs from the tag on the Falco rule, both are given.

| PoC | Technique (thesis) | Falco tag | Command | Rule | Priority | Evidence |
|---|---|---|---|---|---|---|
| 1 | T1003 OS credential dumping | T1555 | `cat /etc/shadow` | Read sensitive file untrusted (community) | Warning | [`falco-attack2-sensitive-file-shadow.png`](falco/falco-attack2-sensitive-file-shadow.png) |
| 2 | T1620 Reflective code loading | T1059.004 | `cp /bin/sh /dev/shm/evil && /dev/shm/evil -c id` | Execution from /dev/shm (community) | Warning | [`falco-attack1-devshm-execution.png`](falco/falco-attack1-devshm-execution.png) |
| 3 | T1528 Steal application access token | T1528 | `cat /run/secrets/kubernetes.io/serviceaccount/token` | Read Kubernetes Service Account Token (custom) | Warning | [`falco-attack3-serviceaccount-token.png`](falco/falco-attack3-serviceaccount-token.png) |
| 4 | T1071.001 Web protocols | T1105 | `curl -s http://example.com` | Detect curl or wget inside container (custom) | Warning | [`falco-attack4-curl-c2.png`](falco/falco-attack4-curl-c2.png) |
| 5 | T1613 Container and resource discovery | not recorded | token-authenticated `curl` to `https://kubernetes.default.svc/api/v1/namespaces/` | Contact K8S API Server From Container (community) | Notice | [`falco-attack5-k8s-api-lateral-movement.png`](falco/falco-attack5-k8s-api-lateral-movement.png) |

The screenshot file names follow the order the scenarios were run in the session (`/dev/shm` first). The thesis numbers them by stage of the adversary progression.

The service account token visible in `falco-attack3-serviceaccount-token.png` belongs to the lab's `kind` cluster, which no longer exists, so it cannot authenticate anywhere.

**PoC 5:** the API server answers `403 Forbidden` for `system:serviceaccount:default:default`. The connection is detected, but it is Kubernetes RBAC, a control outside the four layers, that prevents the enumeration. Because the command also reads the token and uses `curl`, the two custom rules fire on it as well.

**Detection latency:** a single measurement with the PoC 1 command, taken in a later session against the `kubernetes-goat-home` pod, gave an event timestamp in the same second as the command (`00:06:53` → `00:06:53.963`). That establishes an order of magnitude, not a distribution.

---

## Stack Components

| Component | Namespace | Helm chart | App version |
|---|---|---|---|
| kind | — | — | v0.26.0 |
| Kubernetes (node image) | — | — | v1.32.0 |
| Kubernetes Goat | default / big-monolith / secure-middleware | manual (git) | latest |
| Falco | falco | falco-8.0.1 | 0.43.0 |
| Falcosidekick | falco | falcosidekick-0.13.1 | 2.32.0 |
| Kyverno | kyverno | kyverno-3.7.1 | v1.17.1 |
| kube-prometheus-stack | monitoring | kube-prometheus-stack-82.12.0 | v0.89.0 |
| Loki Stack | monitoring | loki-stack-2.10.3 | v2.9.3 (image overridden to `latest`) |
| Trivy Operator | trivy-system | trivy-operator-0.32.1 | 0.30.1 |
| Istio | istio-system | demo profile | 1.24.0 |
| Kiali | istio-system | addon | latest |

---

## Installation Guide

This is the order the stack was actually deployed in, the same order as Chapter 3 of the thesis.

### Prerequisites

```bash
docker --version    # Docker 20+
kubectl version     # kubectl 1.30+
helm version        # Helm v3
kind version        # kind v0.26.0+
istioctl version    # Istio 1.24.0 (needed from Step 8)
```

### Step 1: Cluster

```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.26.0/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

cat > kind-config.yaml << 'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: thesis-lab
nodes:
- role: control-plane
  image: kindest/node:v1.32.0
  extraMounts:
  - hostPath: /proc
    containerPath: /host/proc
    readOnly: true
  - hostPath: /sys
    containerPath: /host/sys
    readOnly: true
  - hostPath: /
    containerPath: /host
    readOnly: true
    propagation: Bidirectional
  extraPortMappings:
  - containerPort: 30000
    hostPort: 30000
    protocol: TCP
EOF

kind create cluster --config kind-config.yaml
kubectl get nodes

# metrics-server (for kubectl top)
kubectl apply -f \
  https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
kubectl patch deployment metrics-server -n kube-system --type='json' \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
```

### Step 2: Kubernetes Goat

```bash
git clone https://github.com/madhuakula/kubernetes-goat.git
cd kubernetes-goat
chmod +x setup-kubernetes-goat.sh
bash setup-kubernetes-goat.sh

kubectl get pods -n big-monolith
kubectl get pods -n secure-middleware
```

### Step 3: Trivy Operator

```bash
helm repo add aquasecurity https://aquasecurity.github.io/helm-charts/
helm repo update

helm install trivy-operator aquasecurity/trivy-operator \
  --namespace trivy-system --create-namespace \
  -f trivy/helm-values.yaml

kubectl rollout status deployment/trivy-operator -n trivy-system
```

### Step 4: Kyverno

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update

helm install kyverno kyverno/kyverno \
  --namespace kyverno --create-namespace \
  -f kyverno/helm-values.yaml

kubectl rollout status deployment/kyverno-admission-controller -n kyverno

kubectl apply -f kyverno/policies/
kubectl get clusterpolicy
```

### Step 5: Falco + Falcosidekick

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

kubectl create namespace falco

helm install falco falcosecurity/falco \
  --namespace falco \
  -f falco/helm-values.yaml \
  -f falco/custom-rules.yaml

helm install falcosidekick falcosecurity/falcosidekick \
  --namespace falco \
  --set webui.enabled=true \
  --set webui.replicaCount=1 \
  --set config.minimumpriority=warning
```

### Step 6: Prometheus + Grafana

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

kubectl create namespace monitoring

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  -f prometheus/helm-values.yaml

kubectl apply -f - << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: falco-metrics
  namespace: falco
  labels:
    app.kubernetes.io/name: falco
spec:
  selector:
    app.kubernetes.io/name: falco
  clusterIP: None
  ports:
    - name: metrics
      port: 8765
      targetPort: 8765
EOF

kubectl apply -f prometheus/servicemonitors.yaml
```

`prometheus/helm-values.yaml` sets `serviceMonitorSelectorNilUsesHelmValues: false`. Without it, the Falco ServiceMonitor is silently ignored.

### Step 7: Loki

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

helm install loki grafana/loki-stack \
  --namespace monitoring \
  --set grafana.enabled=false \
  --set prometheus.enabled=false

# Fixes the Grafana / Loki data-source compatibility failure
helm upgrade loki grafana/loki-stack \
  --namespace monitoring --reuse-values \
  --set loki.image.tag=latest
```

### Step 8: Istio + Kiali + mTLS STRICT

```bash
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.24.0 sh -
cd istio-1.24.0 && export PATH=$PWD/bin:$PATH

istioctl install --set profile=demo -y
kubectl rollout status deployment/istiod -n istio-system

kubectl apply -f samples/addons/kiali.yaml
kubectl apply -f samples/addons/prometheus.yaml
kubectl rollout status deployment/kiali -n istio-system

kubectl label namespace big-monolith istio-injection=enabled
kubectl label namespace secure-middleware istio-injection=enabled
kubectl label namespace default istio-injection=enabled

kubectl rollout restart deployment -n big-monolith
kubectl rollout restart deployment -n secure-middleware
kubectl rollout restart deployment -n default

kubectl apply -f istio/mtls/peer-authentication.yaml
kubectl get peerauthentication -A
```

Sidecar injection applies only to pods created after the label is set, which is why each `rollout restart` is needed.

---

## Dashboard Access

```bash
kubectl port-forward -n monitoring svc/prometheus-grafana 3001:80 &
kubectl port-forward -n falco svc/falcosidekick-ui 2802:2802 &
kubectl port-forward -n monitoring svc/prometheus-kube-prometheus-prometheus 9090:9090 &
kubectl port-forward -n istio-system svc/kiali 20001:20001 &
```

| Tool | URL | Credentials |
|---|---|---|
| Grafana | http://localhost:3001 | admin / admin |
| Falcosidekick UI | http://localhost:2802 | — |
| Prometheus | http://localhost:9090 | — |
| Kiali | http://localhost:20001 | — |

The Falco Grafana dashboard was built by hand against the current `falcosecurity_*` metric names and imported via *Dashboards → New → Import*. Community dashboards that use the legacy `falco_*` prefix render empty panels.

```promql
sum by (rule) (increase(falcosecurity_falco_rules_matches_total[5m]))
rate(falcosecurity_scap_n_evts_total[1m])
falcosecurity_falco_cpu_usage_ratio * 100
sum(falcosecurity_scap_n_drops_buffer_total)
```

---

## Repository Structure

```
thesis-poc/
├── Metrics/
│   ├── Metrics.txt               # queries behind the measurements (Falco cost, Trivy, Kyverno)
│   └── *.png                     # metrics screenshots
├── falco/
│   ├── helm-values.yaml          # driver, metrics, http_output, earlier narrowing attempt
│   ├── custom-rules.yaml         # tuning.yaml (2 disables) + 2 detection rules (deployed ruleset)
│   ├── Attacks PoC.txt           # commands and alert output for the five scenarios
│   └── falco-attack*.png         # alert evidence
├── grafana/                      # dashboard screenshots
├── istio/
│   ├── mtls/peer-authentication.yaml   # STRICT mTLS for default, big-monolith, secure-middleware
│   └── kiali-*.png
├── kyverno/
│   ├── helm-values.yaml
│   ├── policies/                 # the five ClusterPolicies, one file each
│   ├── test.txt                  # admission tests (hunger-check + 3 test pods) and outputs
│   ├── kyverno-test-hostnet-rejected.jpg
│   └── kyverno-*.png
├── loki/                         # Loki / Grafana Explore evidence
├── prometheus/
│   ├── helm-values.yaml
│   ├── servicemonitors.yaml
│   └── prometheus-falco-rules-*.png
├── trivy/
│   ├── helm-values.yaml
│   ├── *.txt                     # VulnerabilityReport extracts per workload
│   └── trivy-*.png
├── PoC.txt                       # full installation reference
└── README.md
```

---

## Key Technical Decisions

**`modern_ebpf` driver.** Kernel `6.8.0-100-generic` has no prebuilt Falco kernel-module driver, and `kind` nodes carry no kernel headers. `modern_ebpf` uses CO-RE via BTF and needs neither.

**Kubernetes 1.32 rather than 1.27.** Kyverno 1.17 depends on the `ValidatingAdmissionPolicy` API, stable since Kubernetes 1.30. On 1.27 the admission controller crashed on missing API resources, and the cluster was rebuilt on 1.32. The version was a constraint, not a free choice.

**Kyverno over OPA Gatekeeper.** The policies are structural assertions about pod specs, and YAML that mirrors the object is direct. Gatekeeper/Rego is the stronger choice when policy needs logic across several resources.

**Istio over Linkerd.** Chosen for Kiali, whose service graph with per-edge mTLS status serves as evidence. Linkerd would have given equivalent mTLS with less operational weight.

**Falco native metrics.** `falco-exporter` is deprecated since Falco 0.38. Metrics are exposed natively on `:8765/metrics` under the `falcosecurity_*` prefix.

**Prometheus and Loki together.** Counters show that something happened. Loki keeps the full event: which file, which process, which container, when.

**Noise reduction: narrowing first, disabling as the fallback.** Exclusion lists scoped to infrastructure did not remove the noise, so two community rules were disabled. The cost (a permanent, cluster-wide coverage reduction) is stated in the thesis.

**mTLS STRICT over PERMISSIVE.** A permissive policy enforces nothing, because plaintext still succeeds. STRICT is what makes the mesh the architecture's one enforcement layer.

---

## MITRE ATT&CK Coverage

Only techniques supported by captured evidence are listed (thesis Table 5.4).

| ID | Technique | Covered by | Evidence |
|---|---|---|---|
| T1195.002 | Supply chain compromise (known vulnerabilities only) | Trivy (partial) | `trivy/trivy-vulnerability-report-detail.png` |
| T1611 | Escape to host (precondition refused) | Kyverno (prevents) | `kyverno/kyverno-test-hostnet-rejected.jpg` |
| T1003 | OS credential dumping | Falco | `falco/falco-attack2-sensitive-file-shadow.png` |
| T1620 | Reflective code loading | Falco | `falco/falco-attack1-devshm-execution.png` |
| T1528 | Steal application access token | Falco | `falco/falco-attack3-serviceaccount-token.png` |
| T1071.001 | Application layer protocol: web protocols | Falco | `falco/falco-attack4-curl-c2.png` |
| T1613 | Container and resource discovery | Falco | `falco/falco-attack5-k8s-api-lateral-movement.png` |
| — | Lateral movement (enforcement mechanism only) | Istio / Kiali | `istio/kiali-traffic-graph-service-mesh.png` |

All scenarios were run without evasion, so this coverage is an upper bound. A statically linked HTTP client, for example, would not match the PoC 4 rule.

---

## Lessons Learned

**`override: enabled: replace` needs the exact rule name.** A mismatch in capitalisation or punctuation makes Falco fail validation at startup. Check with `grep "^- rule:" /etc/falco/falco_rules.yaml` first.

**Metrics snapshot events bypass `minimumpriority` in Falcosidekick.** Fix it at the Falco level with `falco.metrics.output_rule=false`.

**kind nodes need explicit host mounts.** Without `/proc`, `/sys` and `/` mounted from the host, Falco's `modern_ebpf` probe loads without error but cannot instrument syscalls, failing silently.

**Kyverno exceptions must cover the security tooling.** Exclude `kube-system`, `monitoring`, `falco`, `trivy-system`, `istio-system` and `kyverno` before switching to `Enforce`. Switch policies to `Audit` while reinstalling Falco.

**The `falcosecurity_*` prefix is breaking.** Queries and dashboards built on `falco_*` return no data against Falco 0.38+.

---

## Real-World Threat Context

In March 2026 the threat actor **TeamPCP** published malicious versions of the Trivy scanner and its GitHub Actions. They bundled a credential stealer with a self-propagating worm, **CanisterWorm**, which used stolen npm tokens to republish infected packages: 141 malicious package versions across more than 66 packages.

Once installed, the worm ran entirely at runtime. A postinstall script wrote a `systemd` user service that kept a Python backdoor running, and the backdoor executed downloaded payloads from `/tmp`. None of that is visible to an image scan or an admission policy. All of it is visible at the syscall level.

PoC 2 is **not** the CanisterWorm technique. It exercises the same class of behaviour (code that was never part of the scanned image), and only the runtime layer caught it. That illustrates why the runtime layer is there. It does not show the stack would have caught the real campaign.

---

## References

- [Falco documentation](https://falco.org/docs/) · [Falco 0.37.0 release notes](https://falco.org/blog/falco-0-37-0/)
- [Kyverno documentation](https://kyverno.io/docs/)
- [Trivy Operator](https://github.com/aquasecurity/trivy-operator)
- [Istio security concepts](https://istio.io/latest/docs/concepts/security/) · [Kiali](https://kiali.io/docs/)
- [kube-prometheus-stack](https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack) · [Loki](https://grafana.com/docs/loki/latest/)
- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)
- [MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers/)
- [CNCF Cloud Native Security Whitepaper v2](https://github.com/cncf/tag-security/blob/main/security-whitepaper/v2/CNCF_cloud-native-security-whitepaper-May2022-v2.pdf)
- [CanisterWorm: Aikido Security analysis](https://www.aikido.dev/blog/teampcp-deploys-worm-npm-trivy-compromise) · [The Hacker News](https://thehackernews.com/2026/03/trivy-supply-chain-attack-triggers-self.html)

---

## Author

**Vasileios Siampos** (BΔRY, [@SoloBary](https://github.com/SoloBary)), Threat Detection & Response Analyst (L2 SOC)
Bachelor's Thesis, Department of Information & Communication Systems Engineering, University of the Aegean
Supervisor: Prof. Georgios Kambourakis

*Falco · Kyverno · Trivy Operator · Istio · Kiali · Prometheus · Grafana · Loki · kind · Kubernetes Goat*
