# Alertmanager (Sample)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This page contains a sample Alertmanager routing configuration for Aegaeon alerts.

Canonical sample file:
- `docs/operations/monitoring/alertmanager.sample.yaml`

## Sample configuration

```yaml
route:
  receiver: default
  group_by: [alertname]
  group_wait: 10s
  group_interval: 5m
  repeat_interval: 2h
  routes:
    - matchers:
        - severity="warning"
      receiver: slack
    - matchers:
        - severity="info"
      receiver: log

receivers:
  - name: default
    webhook_configs:
      - url: http://localhost:9097/webhook  # SAMPLE
  - name: slack
    slack_configs:
      - api_url: https://hooks.slack.com/services/T000/B000/XXXX  # SAMPLE
        channel: "#alerts"
        send_resolved: true
  - name: log
    webhook_configs:
      - url: http://localhost:9097/log  # SAMPLE

inhibit_rules:
  - source_matchers: [severity="warning"]
    target_matchers: [severity="info"]
    equal: [alertname]

# NOTE: This is a SAMPLE configuration. Replace receivers and URLs with your real endpoints.
```
