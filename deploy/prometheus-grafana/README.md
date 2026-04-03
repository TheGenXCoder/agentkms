# Prometheus + Grafana Deployment for AgentKMS (IN-08)

To deploy Prometheus and Grafana for AgentKMS monitoring, we recommend using the kube-prometheus-stack Helm chart.

## Installation

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install monitoring prometheus-community/kube-prometheus-stack -n monitoring --create-namespace -f values.yaml
```

## Monitoring Configuration

AgentKMS exports metrics in Prometheus format (via the `internal/api` middleware - planned for T2).

Key metrics to monitor:
- `http_request_duration_seconds_bucket{le="0.1"}` (p99 latency)
- `http_requests_total{status=~"5.."}` (error rate)
- `agentkms_audit_events_total` (audit volume)

## Dashboard

The Grafana dashboard JSON can be found in `deploy/prometheus-grafana/dashboards/agentkms.json`.
To import it:
1. Log in to Grafana.
2. Click on "Dashboards" -> "Import".
3. Upload the `agentkms.json` file.
