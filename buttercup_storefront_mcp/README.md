# Buttercup Storefront MCP

This hidden Splunk app registers three MCP tools for investigating web-store
events in the Buttercup Games tutorial dataset.

## Tools

### profile_storefront_ip

Required input:

- ip: valid IPv4 address

Returns request and session totals, cart and checkout activity, distinct
products seen, completed and error checkout sessions, notable paths, and the
observation range.

### list_storefront_sessions

Required input:

- ip: valid IPv4 address

Optional inputs:

- outcome: completed, error, or all; default completed
- limit: integer from 1 through 25; default 3

Returns compact session summaries rather than raw events. Products are
reported as products added in the session.

### get_storefront_baseline

No business input is required. The generated row_limit argument is fixed to
1 because the saved search always returns one aggregate row.

Returns population totals and per-IP average, median, p95, and maximum
statistics. It is designed to contextualize the output of
profile_storefront_ip.

## Implementation

The two IP-specific tools are authenticated persistent REST handlers. The
baseline is an app-scoped saved-search tool so the workshop demonstrates both
REST and saved-search registration.

App Manager reads default/tools.conf and
static/tool_input_payload_signatures.json during installation. The MCP server
exposes each name with the buttercup_storefront_mcp prefix.

