/*
 * Wazuh server API permissions of the FIM rules tab. The API enforces them;
 * the tab uses them to show what the user cannot do before a change fails.
 */

/** Reading the rules: groups and their files, agents, and the history list. */
export const FIM_READ_PERMISSIONS = [
  { action: 'group:read', resource: 'group:id:*' },
  { action: 'agent:read', resource: 'agent:id:*' },
  { action: 'lists:read', resource: 'list:file:*' },
];

/** Changing rules: writing agent.conf and saving the previous version. */
export const FIM_WRITE_PERMISSIONS = [
  { action: 'group:update_config', resource: 'group:id:*' },
  { action: 'lists:update', resource: 'list:file:*' },
];
