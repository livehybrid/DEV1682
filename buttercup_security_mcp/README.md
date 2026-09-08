# Buttercup Security MCP

This hidden Splunk app registers three MCP tools for investigating SSH
authentication events in the Buttercup Games tutorial dataset.

## Tools

### rank_ssh_attackers

Optional input:

- limit: integer from 1 through 25; default 5

Returns a ranked attackers array containing IP address, failed-login count,
distinct targeted usernames, target-host count, and first/last observation.

### get_ssh_source_profile

Required input:

- ip: valid IPv4 address

Returns failed and successful authentication counts, distinct usernames,
target hosts, target-host names, and first/last observation for the IP.

### list_ssh_source_targets

Required input:

- ip: valid IPv4 address

Optional input:

- limit: integer from 1 through 25; default 10

Returns separately ranked host and username summaries. The endpoint performs
one grouped search and aggregates those rows in Python.

## Implementation

The three endpoints are authenticated persistent REST handlers. They execute
bounded, app-scoped searches with the caller's Splunk session and return JSON.
IPv4 values are parsed with Python's ipaddress module before they are placed
in SPL, and callers cannot provide search fragments.

App Manager reads default/tools.conf and
static/tool_input_payload_signatures.json during installation. The MCP server
exposes each name with the buttercup_security_mcp prefix.

