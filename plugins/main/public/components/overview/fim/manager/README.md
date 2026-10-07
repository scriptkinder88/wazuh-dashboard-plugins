# FIM rules management

This is the **Manage** tab of Integrity monitoring. It edits the FIM rules of agent groups and of
single servers from the dashboard, using only the Wazuh API. Nothing is installed on the manager.

## What it edits

The rules are the `<syscheck>` entries of each group's `agent.conf`:

- `<directories>`: monitor a path;
- `<ignore>` and `<nodiff>`: exclude a path, or stop reporting its content diff;
- `<windows_registry>` and `<registry_ignore>`: monitor or exclude a registry key.

Everything else in the file is kept byte for byte: other modules, syscheck settings such as
`frequency`, comments and formatting.

- **Groups:** a rule applies to every agent of the groups chosen.
- **Single servers:** a rule for one server goes into a dedicated group, `fim-host-<agent id>`. The
  tab creates the group and adds the agent to it. When the group has no rules left, the tab deletes
  it. This way a change restarts only that server's agent.
- **Platform:** a rule can be limited to Linux or Windows agents with
  `<agent_config os="...">`. Rules imported from a block with another filter keep that filter.
- **Audit:** each rule written here is preceded by `<!-- wz-fim <base64 JSON> -->`, which holds its
  reason, ticket, owner, author and date. Rules that were already in the groups are shown as
  imported.

## Applying a change

1. **Preview:** every change shows each group's `agent.conf` diff, the agents that will reload the
   configuration and restart, and any path that an agent would get from two groups with different
   options. The group assigned last wins.
2. **Concurrent changes:** before writing, the tab reads the file again. If it changed since the
   preview (for example from the XML editor of Server management), the write is refused.
3. **History:** the previous version of each group is saved in the Wazuh indexer, in the hidden
   index `wz-dashboard-store-fim-history` written by the dashboard server (the last 10 per group).
   The History tab can view and restore it.
4. **Validation:** the manager validates the file (`PUT /groups/{id}/configuration`). The agents
   apply it within a few minutes.

The Agents tab also shows the syscheck configuration an agent last reported (the
`wazuh-agent-config` index; agents report it only when configuration reporting is enabled on
them). Paths that no group defines come from the agent's local configuration. They cannot be
removed centrally, but **Ignore on this server** adds an `<ignore>` rule for that server.

## Permissions

The dashboard user needs these Wazuh RBAC actions: `group:read`, `group:create`,
`group:update_config`, `group:delete`, `agent:read` and `agent:modify_group`. Saving the history
needs a dashboard administrator, like the other settings the dashboard manages.
