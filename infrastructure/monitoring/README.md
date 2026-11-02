# Monitoring

- Prometheus scrapes `backend:8000/metrics` using
  [`prometheus/prometheus.yml`](../prometheus/prometheus.yml).
- Grafana provisions the Prometheus datasource from
  [`grafana/provisioning`](../grafana/provisioning).
- Operational endpoints: `/health`, `/health/live`, `/health/ready`, `/metrics`.
- Structured JSON logs include request id, method, path, status and duration.

Enable locally:

```bash
docker compose --profile observability up
# Prometheus: http://localhost:9090
# Grafana:    http://localhost:3000
```

Suggested panels: request rate/latency by path, error rate, queue depth, worker
availability, scan duration, SBOM processing time, AI latency, MTTD/MTTR trend.
