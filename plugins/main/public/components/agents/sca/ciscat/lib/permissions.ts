/*
 * Wazuh server API permissions of the CIS-CAT tab, whose data are CDB list
 * files. The API enforces them; the tab uses them to show what the user
 * cannot do before a change fails.
 */

export const CISCAT_READ_PERMISSIONS = [
  { action: 'lists:read', resource: 'list:file:*' },
];

export const CISCAT_WRITE_PERMISSIONS = [
  { action: 'lists:update', resource: 'list:file:*' },
];
