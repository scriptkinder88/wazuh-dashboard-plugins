/*
 * Texts of the FIM rules tab.
 */
import { i18n } from '@osd/i18n';

export const messages = {
  // tab
  title: () =>
    i18n.translate('wazuh.fimManager.title', { defaultMessage: 'FIM rules' }),
  description: () =>
    i18n.translate('wazuh.fimManager.description', {
      defaultMessage:
        'Paths and registry keys monitored on groups of agents or on single ' +
        // eslint-disable-next-line quotes -- the text has an apostrophe
        "servers. Changes are written to the groups' agent.conf; agents " +
        'apply them within a few minutes.',
    }),
  reload: () =>
    i18n.translate('wazuh.fimManager.reload', { defaultMessage: 'Reload' }),
  tabRules: () =>
    i18n.translate('wazuh.fimManager.tab.rules', { defaultMessage: 'Rules' }),
  tabAgents: () =>
    i18n.translate('wazuh.fimManager.tab.agents', { defaultMessage: 'Agents' }),
  tabHistory: () =>
    i18n.translate('wazuh.fimManager.tab.history', {
      defaultMessage: 'History',
    }),
  cannotPrepare: () =>
    i18n.translate('wazuh.fimManager.cannotPrepare', {
      defaultMessage: 'This change cannot be prepared',
    }),
  restoreTitle: (group: string, when: string) =>
    i18n.translate('wazuh.fimManager.restoreTitle', {
      defaultMessage: 'Restore {group} as of {when}',
      values: { group, when },
    }),
  removeTitle: (kind: string, path: string) =>
    i18n.translate('wazuh.fimManager.removeTitle', {
      defaultMessage: 'Remove {kind} {path}',
      values: { kind, path },
    }),
  changeTitle: (kind: string, path: string) =>
    i18n.translate('wazuh.fimManager.changeTitle', {
      defaultMessage: 'Change {kind} {path}',
      values: { kind, path },
    }),
  addTitle: (kind: string, path: string) =>
    i18n.translate('wazuh.fimManager.addTitle', {
      defaultMessage: 'Add {kind} {path}',
      values: { kind, path },
    }),

  // rules table
  columnType: () =>
    i18n.translate('wazuh.fimManager.rules.type', { defaultMessage: 'Type' }),
  columnPath: () =>
    i18n.translate('wazuh.fimManager.rules.path', { defaultMessage: 'Path' }),
  columnOptions: () =>
    i18n.translate('wazuh.fimManager.rules.options', {
      defaultMessage: 'Options',
    }),
  columnAppliesTo: () =>
    i18n.translate('wazuh.fimManager.rules.appliesTo', {
      defaultMessage: 'Applies to',
    }),
  columnAudit: () =>
    i18n.translate('wazuh.fimManager.rules.audit', { defaultMessage: 'Audit' }),
  columnActions: () =>
    i18n.translate('wazuh.fimManager.rules.actions', {
      defaultMessage: 'Actions',
    }),
  importedNoAudit: () =>
    i18n.translate('wazuh.fimManager.rules.imported', {
      defaultMessage: 'Imported (no audit data)',
    }),
  unknownUser: () =>
    i18n.translate('wazuh.fimManager.unknownUser', {
      defaultMessage: 'unknown',
    }),
  owner: (owner: string) =>
    i18n.translate('wazuh.fimManager.rules.owner', {
      defaultMessage: ' · owner {owner}',
      values: { owner },
    }),
  change: () =>
    i18n.translate('wazuh.fimManager.rules.change', {
      defaultMessage: 'Change',
    }),
  remove: () =>
    i18n.translate('wazuh.fimManager.rules.remove', {
      defaultMessage: 'Remove',
    }),
  unreadableGroups: () =>
    i18n.translate('wazuh.fimManager.rules.unreadable', {
      defaultMessage: 'Some groups cannot be managed here',
    }),
  rulesSearch: () =>
    i18n.translate('wazuh.fimManager.rules.search', {
      defaultMessage: 'Path, group, server, tag, reason…',
    }),
  addRule: () =>
    i18n.translate('wazuh.fimManager.rules.add', {
      defaultMessage: 'Add rule',
    }),
  noRules: () =>
    i18n.translate('wazuh.fimManager.rules.empty', {
      defaultMessage: 'No FIM rules in the groups yet',
    }),
  optionWhodata: () =>
    i18n.translate('wazuh.fimManager.option.whodata', {
      defaultMessage: 'who-data',
    }),
  optionRealtime: () =>
    i18n.translate('wazuh.fimManager.option.realtime', {
      defaultMessage: 'real time',
    }),
  optionReportChanges: () =>
    i18n.translate('wazuh.fimManager.option.reportChanges', {
      defaultMessage: 'report changes',
    }),
  optionRecursion: (level: string) =>
    i18n.translate('wazuh.fimManager.option.recursion', {
      defaultMessage: 'recursion {level}',
      values: { level },
    }),
  optionRestrict: (regex: string) =>
    i18n.translate('wazuh.fimManager.option.restrict', {
      defaultMessage: 'restrict {regex}',
      values: { regex },
    }),
  optionTag: (tag: string) =>
    i18n.translate('wazuh.fimManager.option.tag', {
      defaultMessage: 'tag {tag}',
      values: { tag },
    }),

  // history
  historyDescription: (depth: number) =>
    i18n.translate('wazuh.fimManager.history.description', {
      defaultMessage:
        'The version of agent.conf each group had before a change made here ' +
        '(last {depth} per group). Restoring shows the changes first. The ' +
        'user and note are recorded by the dashboard for information: the ' +
        'Wazuh server API does not verify them.',
      values: { depth },
    }),
  historySearch: () =>
    i18n.translate('wazuh.fimManager.history.search', {
      defaultMessage: 'Group, user, note…',
    }),
  columnSaved: () =>
    i18n.translate('wazuh.fimManager.history.saved', {
      defaultMessage: 'Saved',
    }),
  columnGroup: () =>
    i18n.translate('wazuh.fimManager.history.group', {
      defaultMessage: 'Group',
    }),
  columnChangedBy: () =>
    i18n.translate('wazuh.fimManager.history.changedBy', {
      defaultMessage: 'Changed by',
    }),
  columnChange: () =>
    i18n.translate('wazuh.fimManager.history.change', {
      defaultMessage: 'Change',
    }),
  view: () =>
    i18n.translate('wazuh.fimManager.history.view', { defaultMessage: 'View' }),
  restore: () =>
    i18n.translate('wazuh.fimManager.history.restore', {
      defaultMessage: 'Restore',
    }),
  noHistory: () =>
    i18n.translate('wazuh.fimManager.history.empty', {
      defaultMessage: 'No saved versions yet',
    }),

  // agents
  activeTitle: (name: string, id: string) =>
    i18n.translate('wazuh.fimManager.agents.activeTitle', {
      defaultMessage: 'Active FIM configuration: {name} ({id})',
      values: {
        name,
        id,
      },
    }),
  activeDescription: () =>
    i18n.translate('wazuh.fimManager.agents.activeDescription', {
      defaultMessage:
        'What the agent is running now. Paths not defined by any of its groups ' +
        'come from its local ossec.conf: they cannot be removed centrally, ' +
        'but they can be ignored on this server.',
    }),
  cannotReadActive: () =>
    i18n.translate('wazuh.fimManager.agents.cannotRead', {
      defaultMessage: 'Cannot read the agent configuration',
    }),
  agentMustBeActive: () =>
    i18n.translate('wazuh.fimManager.agents.mustBeActive', {
      defaultMessage: 'The agent must be active.',
    }),
  columnSource: () =>
    i18n.translate('wazuh.fimManager.agents.source', {
      defaultMessage: 'Source',
    }),
  local: () =>
    i18n.translate('wazuh.fimManager.agents.local', {
      defaultMessage: 'local',
    }),
  ignoreOnServer: () =>
    i18n.translate('wazuh.fimManager.agents.ignore', {
      defaultMessage: 'Ignore on this server',
    }),
  noMonitoredPaths: () =>
    i18n.translate('wazuh.fimManager.agents.noPaths', {
      defaultMessage: 'No monitored paths',
    }),
  agentsSearch: () =>
    i18n.translate('wazuh.fimManager.agents.search', {
      defaultMessage: 'Server, id, group, platform…',
    }),
  columnServer: () =>
    i18n.translate('wazuh.fimManager.agents.server', {
      defaultMessage: 'Server',
    }),
  columnStatus: () =>
    i18n.translate('wazuh.fimManager.agents.status', {
      defaultMessage: 'Status',
    }),
  columnPlatform: () =>
    i18n.translate('wazuh.fimManager.agents.platform', {
      defaultMessage: 'Platform',
    }),
  columnFimGroups: () =>
    i18n.translate('wazuh.fimManager.agents.fimGroups', {
      defaultMessage: 'Groups with FIM rules',
    }),
  columnConfiguration: () =>
    i18n.translate('wazuh.fimManager.agents.configuration', {
      defaultMessage: 'Configuration',
    }),
  synced: () =>
    i18n.translate('wazuh.fimManager.agents.synced', {
      defaultMessage: 'synced',
    }),
  unknownStatus: () =>
    i18n.translate('wazuh.fimManager.agents.unknownStatus', {
      defaultMessage: 'unknown',
    }),
  activeConfig: () =>
    i18n.translate('wazuh.fimManager.agents.activeConfig', {
      defaultMessage: 'Active config',
    }),
  noAgents: () =>
    i18n.translate('wazuh.fimManager.agents.empty', {
      defaultMessage: 'No agents',
    }),

  // plan
  newGroup: (name: string) =>
    i18n.translate('wazuh.fimManager.plan.newGroup', {
      defaultMessage: '{name}: new group',
      values: { name },
    }),
  groupDeleted: (name: string) =>
    i18n.translate('wazuh.fimManager.plan.groupDeleted', {
      defaultMessage: '{name}: no rules left, group deleted',
      values: { name },
    }),
  nothingToChange: () =>
    i18n.translate('wazuh.fimManager.plan.nothing', {
      defaultMessage: 'Nothing to change',
    }),
  groupsChange: (count: number) =>
    i18n.translate('wazuh.fimManager.plan.groupsChange', {
      defaultMessage: '{count} group(s) change.',
      values: { count },
    }),
  agentsCount: (count: number) =>
    i18n.translate('wazuh.fimManager.plan.agentsCount', {
      defaultMessage: '{count} agent(s)',
      values: { count },
    }),
  willRestart: (names: string) =>
    i18n.translate('wazuh.fimManager.plan.willRestart', {
      defaultMessage:
        'will download the new configuration and restart within a few ' +
        'minutes{names}.',
      values: { names },
    }),
  restoreWarningTitle: () =>
    i18n.translate('wazuh.fimManager.plan.restoreWarningTitle', {
      defaultMessage: 'Check the whole file before restoring it',
    }),
  restoreWarning: () =>
    i18n.translate('wazuh.fimManager.plan.restoreWarning', {
      defaultMessage:
        'The saved version replaces the entire agent.conf of the group, not ' +
        'only its FIM rules. Saved versions are kept in the fim-history list, ' +
        'which anyone allowed to edit CDB lists can change: compare it with ' +
        'the current file below.',
    }),
  restoreReviewed: () =>
    i18n.translate('wazuh.fimManager.plan.restoreReviewed', {
      defaultMessage: 'I checked the changes below',
    }),
  conflictsTitle: () =>
    i18n.translate('wazuh.fimManager.plan.conflictsTitle', {
      defaultMessage:
        'The same path gets different options from several groups',
    }),
  conflictsHelp: () =>
    i18n.translate('wazuh.fimManager.plan.conflictsHelp', {
      defaultMessage: 'The agent keeps the options of the group assigned last.',
    }),
  agentAdded: (agent: string) =>
    i18n.translate('wazuh.fimManager.plan.agentAdded', {
      defaultMessage: ' — agent {agent} added to it',
      values: { agent },
    }),
  changeNote: () =>
    i18n.translate('wazuh.fimManager.plan.changeNote', {
      defaultMessage: 'Change note (saved with the previous versions)',
    }),
  stoppedTitle: () =>
    i18n.translate('wazuh.fimManager.plan.stoppedTitle', {
      defaultMessage: 'The change stopped',
    }),
  stoppedHelp: () =>
    i18n.translate('wazuh.fimManager.plan.stoppedHelp', {
      defaultMessage:
        'What was done is listed next to each group; the groups after the ' +
        'failure were not touched. Reload to see the current state.',
    }),
  appliedTitle: () =>
    i18n.translate('wazuh.fimManager.plan.appliedTitle', {
      defaultMessage: 'Applied',
    }),
  appliedHelp: () =>
    i18n.translate('wazuh.fimManager.plan.appliedHelp', {
      defaultMessage:
        'Agents pick up the new configuration within a few minutes. The Agents ' +
        'tab shows when each one is synchronized.',
    }),
  close: () =>
    i18n.translate('wazuh.fimManager.close', { defaultMessage: 'Close' }),
  cancel: () =>
    i18n.translate('wazuh.fimManager.cancel', { defaultMessage: 'Cancel' }),
  apply: () =>
    i18n.translate('wazuh.fimManager.plan.apply', { defaultMessage: 'Apply' }),

  // rule form
  modeHelpScheduled: () =>
    i18n.translate('wazuh.fimManager.form.modeHelp.scheduled', {
      defaultMessage: 'Checked at each periodic scan.',
    }),
  modeHelpRealtime: () =>
    i18n.translate('wazuh.fimManager.form.modeHelp.realtime', {
      defaultMessage: 'Real time applies to directories, not single files.',
    }),
  modeHelpWhodata: () =>
    i18n.translate('wazuh.fimManager.form.modeHelp.whodata', {
      defaultMessage:
        'Who-data needs auditd on Linux and the audit policy on Windows.',
    }),
  pathHelp: () =>
    i18n.translate('wazuh.fimManager.form.pathHelp', {
      defaultMessage:
        'Several paths can be separated by commas. Environment variables such as ' +
        '%WINDIR% are expanded by the agent.',
    }),
  changeRule: () =>
    i18n.translate('wazuh.fimManager.form.changeTitle', {
      defaultMessage: 'Change FIM rule',
    }),
  newRule: () =>
    i18n.translate('wazuh.fimManager.form.newTitle', {
      defaultMessage: 'New FIM rule',
    }),
  type: () =>
    i18n.translate('wazuh.fimManager.form.type', { defaultMessage: 'Type' }),
  registryKey: () =>
    i18n.translate('wazuh.fimManager.form.registryKey', {
      defaultMessage: 'Registry key',
    }),
  path: () =>
    i18n.translate('wazuh.fimManager.form.path', { defaultMessage: 'Path' }),
  sregexHelp: () =>
    i18n.translate('wazuh.fimManager.form.sregexHelp', {
      defaultMessage:
        'Regular expression (sregex) matched against the full path.',
    }),
  platform: () =>
    i18n.translate('wazuh.fimManager.form.platform', {
      defaultMessage: 'Platform',
    }),
  platformHelp: () =>
    i18n.translate('wazuh.fimManager.form.platformHelp', {
      defaultMessage: 'Agents whose operating system the rule applies to.',
    }),
  platformAny: () =>
    i18n.translate('wazuh.fimManager.form.platformAny', {
      defaultMessage: 'Any',
    }),
  asImported: (filter: string) =>
    i18n.translate('wazuh.fimManager.form.asImported', {
      defaultMessage: 'As imported ({filter})',
      values: { filter },
    }),
  mode: () =>
    i18n.translate('wazuh.fimManager.form.mode', { defaultMessage: 'Mode' }),
  modeScheduled: () =>
    i18n.translate('wazuh.fimManager.form.modeScheduled', {
      defaultMessage: 'Scheduled scan',
    }),
  modeRealtime: () =>
    i18n.translate('wazuh.fimManager.form.modeRealtime', {
      defaultMessage: 'Real time',
    }),
  modeWhodata: () =>
    i18n.translate('wazuh.fimManager.form.modeWhodata', {
      defaultMessage: 'Who-data (real time + user)',
    }),
  reportChanges: () =>
    i18n.translate('wazuh.fimManager.form.reportChanges', {
      defaultMessage: 'Report changes (content diff)',
    }),
  recursionLevel: () =>
    i18n.translate('wazuh.fimManager.form.recursionLevel', {
      defaultMessage: 'Recursion level',
    }),
  recursionHelp: () =>
    i18n.translate('wazuh.fimManager.form.recursionHelp', {
      defaultMessage: 'Empty: default',
    }),
  tags: () =>
    i18n.translate('wazuh.fimManager.form.tags', { defaultMessage: 'Tags' }),
  tagsHelp: () =>
    i18n.translate('wazuh.fimManager.form.tagsHelp', {
      defaultMessage: 'Added to the FIM events',
    }),
  restrict: () =>
    i18n.translate('wazuh.fimManager.form.restrict', {
      defaultMessage: 'Restrict',
    }),
  restrictHelp: () =>
    i18n.translate('wazuh.fimManager.form.restrictHelp', {
      defaultMessage: 'Only files matching this regular expression',
    }),
  isSregex: () =>
    i18n.translate('wazuh.fimManager.form.isSregex', {
      defaultMessage: 'The path is a regular expression (sregex)',
    }),
  architecture: () =>
    i18n.translate('wazuh.fimManager.form.architecture', {
      defaultMessage: 'Architecture',
    }),
  archDefault: () =>
    i18n.translate('wazuh.fimManager.form.archDefault', {
      defaultMessage: 'Default (32bit)',
    }),
  archBoth: () =>
    i18n.translate('wazuh.fimManager.form.archBoth', {
      defaultMessage: 'Both',
    }),
  appliesTo: () =>
    i18n.translate('wazuh.fimManager.form.appliesTo', {
      defaultMessage: 'Applies to',
    }),
  groups: () =>
    i18n.translate('wazuh.fimManager.form.groups', {
      defaultMessage: 'Groups',
    }),
  groupsHelp: () =>
    i18n.translate('wazuh.fimManager.form.groupsHelp', {
      defaultMessage: 'Every agent of these groups',
    }),
  servers: () =>
    i18n.translate('wazuh.fimManager.form.servers', {
      defaultMessage: 'Servers',
    }),
  serversHelp: () =>
    i18n.translate('wazuh.fimManager.form.serversHelp', {
      defaultMessage: 'Single servers: each gets its own {group} group',
      values: { group: 'fim-host-<id>' },
    }),
  audit: () =>
    i18n.translate('wazuh.fimManager.form.audit', { defaultMessage: 'Audit' }),
  reason: () =>
    i18n.translate('wazuh.fimManager.form.reason', {
      defaultMessage: 'Reason',
    }),
  ticket: () =>
    i18n.translate('wazuh.fimManager.form.ticket', {
      defaultMessage: 'Ticket',
    }),
  ownerLabel: () =>
    i18n.translate('wazuh.fimManager.form.owner', { defaultMessage: 'Owner' }),
  checkTheRule: () =>
    i18n.translate('wazuh.fimManager.form.checkTheRule', {
      defaultMessage: 'Check the rule',
    }),
  reviewChanges: () =>
    i18n.translate('wazuh.fimManager.form.review', {
      defaultMessage: 'Review changes',
    }),
  chooseTarget: () =>
    i18n.translate('wazuh.fimManager.form.chooseTarget', {
      defaultMessage: 'choose at least one group or server',
    }),
  checkHint: () =>
    i18n.translate('wazuh.fimManager.form.checkHint', {
      defaultMessage: 'Check this rule',
    }),
  checkHints: (count: number) =>
    i18n.translate('wazuh.fimManager.form.checkHints', {
      defaultMessage: 'Check this rule ({count})',
      values: { count },
    }),

  // path test
  testCannotRead: (error: string) =>
    i18n.translate('wazuh.fimManager.test.cannotRead', {
      defaultMessage: 'cannot read the inventory ({error})',
      values: { error },
    }),
  testEntries: (count: string) =>
    i18n.translate('wazuh.fimManager.test.entries', {
      defaultMessage: '{count} entries',
      values: { count },
    }),
  testNoneSampled: () =>
    i18n.translate('wazuh.fimManager.test.noneSampled', {
      defaultMessage:
        'none among the first entries found, the inventory may hold more',
    }),
  testNone: () =>
    i18n.translate('wazuh.fimManager.test.none', {
      defaultMessage:
        'none (the path does not exist there or is not monitored yet)',
    }),
  testUnder: () =>
    i18n.translate('wazuh.fimManager.test.under', {
      defaultMessage: 'FIM inventory entries under',
    }),
  testLastScan: (date: string) =>
    i18n.translate('wazuh.fimManager.test.lastScan', {
      defaultMessage: ' · last scan {date}',
      values: { date },
    }),
  testOnAgent: (count: number) =>
    i18n.translate('wazuh.fimManager.test.onAgent', {
      defaultMessage: 'Test the path on {count} agent of the targets',
      values: { count },
    }),
  testOnAgents: (count: number) =>
    i18n.translate('wazuh.fimManager.test.onAgents', {
      defaultMessage: 'Test the path on {count} agents of the targets',
      values: { count },
    }),
  testChooseFirst: () =>
    i18n.translate('wazuh.fimManager.test.chooseFirst', {
      defaultMessage: 'Test the path (choose groups or servers first)',
    }),
};
