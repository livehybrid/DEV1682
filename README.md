# Installing and Configuring the Buttercup MCP Apps in Splunk

A step-by-step guide to installing the `buttercup_security_mcp` and
`buttercup_storefront_mcp` apps on a Splunk stack, connecting them to the
workshop chat system over MCP, and running a first investigation.

## Prerequisites

- Access to your workshop Splunk server and its provided login credentials
  (see your workshop welcome email/handout).
- A splunk.com account (used by appinspect when uploading the apps).
- The workshop chat system: **https://workshop.cloud.livehybrid.com**, and your
  workshop code (e.g. `dev1682`) to join your session.
- The `buttercup_security_mcp` and `buttercup_storefront_mcp` installable
  apps (see "dist" directory in this repo ) - You will need to download these.
- A terminal with `tar` and a checkout of this repo, so you can edit and
  rebuild `buttercup_storefront_mcp` in step 6. If you're unable to build it
  yourself, a pre-built `buttercup_storefront_mcp-1.0.1.tar.gz` will be
  provided as a fallback so you can still complete the workshop.

## 1. Log in to Splunk

Go to your Splunk Show server. You'll be greeted with the standard login screen,
log in with your provided credentials.

## 2. Upload and install the Buttercup MCP apps

1. In the top left, click the app menu and select **Manage Apps**.
2. Click **Install app from file**.
3. Click the green **Upload app** button, top right.
4. You'll be asked to log in with your splunk.com credentials — click the
   green **Login** button.
5. Click **Browse** and select the first app — start with
   `buttercup_security_mcp` packaged app that you downloaded.
6. Click **Agree and upload**, and wait for the app to be vetted.
7. While that's processing, click **Upload app** again, browse again, and
   select `buttercup_storefront_mcp` (version 1.0.0). Click **Upload app**.
8. Once both apps show as approved, click **Install** for each, then confirm
   with **Acknowledge and install**.

Both `buttercup_security_mcp` and `buttercup_storefront_mcp` are now
installed.

## 3. Configure the MCP server connection in the chat system

1. Open the workshop chat system: **https://workshop.cloud.livehybrid.com**.
2. Enter your workshop code (e.g. `dev1682`) — this ties your chat session
3. Switch back to your Splunk tab, go to **Apps** and click on **Splunk MCP server**.
4. Click the copy button next to the **JSON config** text to copy the MCP server connectivity details.
5. Back in the chat system, paste that JSON into the **MCP configuration
   JSON** box. You'll be prompted for a token.
6. Switch back to your Splunk tab, click **Create MCP encrypted token**, then confirm with
   **Create**. Copy the resulting token.
7. Back in the chat system tan, paste the token into the **MCP token** box and
   click the orange **Connect** button.

You should now see the connection to your show stack, along with an option
to choose which model to use in the top left hand side. The default are sufficient.

## 4. Enable and refresh MCP tools

By default, only the 10 standard Splunk MCP tools are available — the
Buttercup tools aren't enabled yet.

1. In your Splunk tab, within the Splunk MCP server app, go to the **Tools** tab.
2. You'll see the Buttercup Security and Buttercup Storefront MCP tools
   listed as disabled.
3. Click **Enable all tools** next to each.
4. Back in the chat system, click **Refresh tools** (just above the tool
   list).

The tool list now includes the Buttercup Security and Buttercup Storefront
tools alongside the defaults (15 tools in total).

## 5. Run an investigation

1. Paste the following prompt into the chat box and hit send:

   > Use the installed Buttercup tools to identify the source with the most
   > failed SSH logins. Determine whether it ever logged in successfully and
   > show its most-targeted systems and accounts. Then investigate the same
   > IP in the storefront, compare its behavior with the storefront
   > baseline, and show three completed checkout sessions. Recommend
   > whether it should be escalated, clearly separating observed facts from
   > inference.

2. The assistant calls the newly enabled tools and returns an investigation
   summary — for example, the identified attack, targeted systems, targeted
   accounts, and an escalation recommendation.
3. You can inspect or use any of the other available tools via the
   **Tools** button, top right.

## 6. Add and use the storefront baseline tool

Lets see how easy it is to add new tools to your Splunk MCP Server. We need to
hand-editing an installed app to add a third storefront tool,
`buttercup_storefront_mcp_get_storefront_baseline`, and seeing how little
work it takes for the assistant to pick it up. It returns population-wide
totals and averages so an individual IP's activity can be judged as
unusually high or not.

Add the following to `buttercup_storefront_mcp/default/tools.conf`:

```ini
[savedsearches:get_storefront_baseline]
description = Returns one row of Buttercup storefront population totals plus average, median, p95, and maximum per-IP activity. Use this to judge whether an IP from profile_storefront_ip is unusually active.
search = Buttercup Storefront - Population Baseline
headers = Accept, Content-Type
header.Accept = application/json
header.Content-Type = application/x-www-form-urlencoded
tags = buttercup, storefront, commerce, baseline
```

Then bump the version to `1.0.1` in `buttercup_storefront_mcp/default/app.conf`
(2 occurences `[launcher]` and `[id]` stanzas).

Now edit the `buttercup_storefront_mcp/app.manifest` file (line 8) and change the `1.0.0` version to `1.0.1` to match. Then we re-package the app:

1. Rebuild the `buttercup_storefront_mcp` tarball with the updated `tools.conf` and
   `app.conf`. From the repo root directory run:

   ```
   tar --exclude='__pycache__' --exclude='*.pyc' -czf buttercup_storefront_mcp-1.0.1.tar.gz buttercup_storefront_mcp
   ```

   Can't build it yourself, or short on time? Use the pre-built
   `dist/buttercup_storefront_mcp-1.0.1.tar.gz` provided for the workshop instead,
   and skip to step 2.

2. In Splunk, go to **Apps** (top left) → **Manage Apps**.
3. Click **Install app from file**, then the green **Upload app** button,
   top right.
4. Browse for the tarball you just built, click **Agree and Upload**.
5. Once approved, click **Install**, then confirm with green
   **Acknowledge and Install**.
6. Go back to the **Tools** tab within the Splunk MCP server app — you need
   to enable the new tool. Click **Enable** next to
   **Buttercup Storefront MCP Get Storefront Baseline**.
7. Go back to the workshop chat tab, click the **Tools** button top right
   (it currently shows 15 tools installed), and click **Refresh Tools**.
   The new **Get Storefront Baseline** tool now appears in the list.

Naming and tagging tools correctly (as in the `tools.conf` snippet above)
lets the LLM pick them up automatically based on the question asked — you
don't need to name the tool explicitly in your prompt, though the example
below does so for clarity.

Paste the following prompt into the chat box and hit send:

> Now use the newly added
> buttercup_storefront_mcp_get_storefront_baseline tool to compare the
> previously investigated IP's storefront behavior with the population
> baseline. Quantify how its request volume and completed checkout
> activity compare with the average, median, p95, and maximum. Then update
> your escalation recommendation, clearly separating observed facts from
> inference. Do not assume that a shared IP proves a shared human identity.

The assistant now uses the baseline tool to quantify how the investigated
IP's activity compares with the population, and updates its escalation
recommendation accordingly.
