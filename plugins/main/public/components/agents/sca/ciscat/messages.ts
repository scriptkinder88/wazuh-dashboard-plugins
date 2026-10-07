/*
 * Texts of the CIS-CAT tab.
 */
import { i18n } from '@osd/i18n';

export const messages = {
  // tab
  title: () =>
    i18n.translate('wazuh.ciscat.title', { defaultMessage: 'CIS-CAT Pro' }),
  description: () =>
    i18n.translate('wazuh.ciscat.description', {
      defaultMessage:
        'Exclusions and schedules for the CIS-CAT assessments run by the ' +
        'manager. Changes are stored on the manager and applied by its ' +
        'scheduler.',
    }),
  reload: () =>
    i18n.translate('wazuh.ciscat.reload', { defaultMessage: 'Reload' }),
  tabExclusions: () =>
    i18n.translate('wazuh.ciscat.tab.exclusions', {
      defaultMessage: 'Exclusions',
    }),
  tabSchedule: () =>
    i18n.translate('wazuh.ciscat.tab.schedule', { defaultMessage: 'Schedule' }),
  tabStatus: () =>
    i18n.translate('wazuh.ciscat.tab.status', { defaultMessage: 'Status' }),
  cannotRead: () =>
    i18n.translate('wazuh.ciscat.cannotRead', {
      defaultMessage: 'Cannot read the CIS-CAT data',
    }),
  noBridgeTitle: () =>
    i18n.translate('wazuh.ciscat.noBridge.title', {
      defaultMessage: 'The CIS-CAT bridge has not published any data yet',
    }),
  noBridge: (minutes: number) =>
    i18n.translate('wazuh.ciscat.noBridge.text', {
      defaultMessage:
        'Install the bridge on the manager and let its scheduler run once ' +
        '(every {minutes} minutes): it publishes the benchmarks and the OS ' +
        'list shown here.',
      values: { minutes },
    }),
  cancel: () =>
    i18n.translate('wazuh.ciscat.cancel', { defaultMessage: 'Cancel' }),
  save: () => i18n.translate('wazuh.ciscat.save', { defaultMessage: 'Save' }),

  // coverage
  coverageTitle: (days: number) =>
    i18n.translate('wazuh.ciscat.coverage.title', {
      defaultMessage: 'Agents assessed in the last {days} days',
      values: { days },
    }),
  coverageNoAgents: () =>
    i18n.translate('wazuh.ciscat.coverage.noAgents', {
      defaultMessage: 'no agents in the group',
    }),
  coveragePoint: (percent: number, assessed: number, expected: number) =>
    i18n.translate('wazuh.ciscat.coverage.point', {
      defaultMessage: '{percent}% ({assessed} of {expected} agents)',
      values: {
        percent,
        assessed,
        expected,
      },
    }),
  coverageDisconnected: (count: number) =>
    i18n.translate('wazuh.ciscat.coverage.disconnected', {
      defaultMessage: '{count} not assessed and disconnected',
      values: {
        count,
      },
    }),
  coverageAria: (first: string, last: string, latest: string) =>
    i18n.translate('wazuh.ciscat.coverage.aria', {
      defaultMessage:
        'Coverage from {first} to {last}: {latest} on the last day',
      values: { first, last, latest },
    }),
  coverageBenchmark: () =>
    i18n.translate('wazuh.ciscat.coverage.benchmark', {
      defaultMessage: 'Benchmark',
    }),
  coverageAllBenchmarks: () =>
    i18n.translate('wazuh.ciscat.coverage.allBenchmarks', {
      defaultMessage: 'All benchmarks',
    }),
  coveragePeriod: () =>
    i18n.translate('wazuh.ciscat.coverage.period', {
      defaultMessage: 'Period',
    }),
  coverage30Days: () =>
    i18n.translate('wazuh.ciscat.coverage.30days', {
      defaultMessage: '30 days',
    }),
  coverage90Days: () =>
    i18n.translate('wazuh.ciscat.coverage.90days', {
      defaultMessage: '90 days',
    }),
  coverageYear: () =>
    i18n.translate('wazuh.ciscat.coverage.year', { defaultMessage: '1 year' }),
  coverageShowData: () =>
    i18n.translate('wazuh.ciscat.coverage.showData', {
      defaultMessage: 'Show data',
    }),
  coverageDay: () =>
    i18n.translate('wazuh.ciscat.coverage.day', { defaultMessage: 'Day' }),
  coverageAssessed: () =>
    i18n.translate('wazuh.ciscat.coverage.assessed', {
      defaultMessage: 'Assessed',
    }),
  coverageAgents: () =>
    i18n.translate('wazuh.ciscat.coverage.agents', {
      defaultMessage: 'Agents',
    }),
  coverageColumn: () =>
    i18n.translate('wazuh.ciscat.coverage.coverage', {
      defaultMessage: 'Coverage',
    }),
  coverageNotAssessedDisconnected: () =>
    i18n.translate('wazuh.ciscat.coverage.notAssessedDisconnected', {
      defaultMessage: 'Not assessed, disconnected',
    }),
  coverageEmpty: () =>
    i18n.translate('wazuh.ciscat.coverage.empty', {
      defaultMessage:
        'No coverage recorded yet. The manager records it once a day, and the ' +
        'trend starts from that day: update the CIS-CAT bridge on the ' +
        'manager if nothing shows up tomorrow.',
    }),

  // exclusions
  exclusionsSavedApply: () =>
    i18n.translate('wazuh.ciscat.exclusions.savedApply', {
      defaultMessage: 'Exclusions saved, apply requested',
    }),
  exclusionsSaved: () =>
    i18n.translate('wazuh.ciscat.exclusions.saved', {
      defaultMessage: 'Exclusions saved',
    }),
  exclusionsApplyHelp: (minutes: number) =>
    i18n.translate('wazuh.ciscat.exclusions.applyHelp', {
      defaultMessage:
        'The manager regenerates the policies within {minutes} minutes.',
      values: { minutes },
    }),
  exclusionsSaveHelp: () =>
    i18n.translate('wazuh.ciscat.exclusions.saveHelp', {
      defaultMessage: 'Use "Save and apply" to publish them to the agents.',
    }),
  exclusionsPartial: () =>
    i18n.translate('wazuh.ciscat.exclusions.partial', {
      defaultMessage: 'Exclusions saved, the rest was not',
    }),
  exclusionsNotSaved: () =>
    i18n.translate('wazuh.ciscat.exclusions.notSaved', {
      defaultMessage: 'Exclusions not saved',
    }),
  noBenchmarkTitle: () =>
    i18n.translate('wazuh.ciscat.exclusions.noBenchmark', {
      defaultMessage: 'No benchmark available',
    }),
  noBenchmark: () =>
    i18n.translate('wazuh.ciscat.exclusions.noBenchmarkText', {
      defaultMessage:
        'The manager has not published any benchmark sheet yet, or no OS in ' +
        'its library has its benchmark file.',
    }),
  operatingSystem: () =>
    i18n.translate('wazuh.ciscat.exclusions.os', {
      defaultMessage: 'Operating system',
    }),
  inactive: () =>
    i18n.translate('wazuh.ciscat.exclusions.inactive', {
      defaultMessage: ' (inactive)',
    }),
  appliesToGroup: () =>
    i18n.translate('wazuh.ciscat.exclusions.appliesToGroup', {
      defaultMessage: 'Applies to group',
    }),
  appliesToGroupHelp: () =>
    i18n.translate('wazuh.ciscat.exclusions.appliesToGroupHelp', {
      defaultMessage:
        'Agents of this group get the benchmark at the next apply',
    }),
  profile: () =>
    i18n.translate('wazuh.ciscat.exclusions.profile', {
      defaultMessage: 'Profile',
    }),
  show: () =>
    i18n.translate('wazuh.ciscat.exclusions.show', { defaultMessage: 'Show' }),
  showApplicable: () =>
    i18n.translate('wazuh.ciscat.exclusions.showApplicable', {
      defaultMessage: 'Controls in the profile',
    }),
  showExcluded: () =>
    i18n.translate('wazuh.ciscat.exclusions.showExcluded', {
      defaultMessage: 'Excluded only',
    }),
  showAll: () =>
    i18n.translate('wazuh.ciscat.exclusions.showAll', {
      defaultMessage: 'All controls',
    }),
  filter: () =>
    i18n.translate('wazuh.ciscat.exclusions.filter', {
      defaultMessage: 'Filter',
    }),
  filterPlaceholder: () =>
    i18n.translate('wazuh.ciscat.exclusions.filterPlaceholder', {
      defaultMessage: 'CIS number or title',
    }),
  statInProfile: () =>
    i18n.translate('wazuh.ciscat.exclusions.inProfile', {
      defaultMessage: 'In profile',
    }),
  statFleetWide: () =>
    i18n.translate('wazuh.ciscat.exclusions.fleetWide', {
      defaultMessage: 'Excluded for the OS',
    }),
  statPartial: () =>
    i18n.translate('wazuh.ciscat.exclusions.partialAgents', {
      defaultMessage: 'Excluded for some agents',
    }),
  statScored: () =>
    i18n.translate('wazuh.ciscat.exclusions.scored', {
      defaultMessage: 'Scored (automated)',
    }),
  excludeSelected: (count: number) =>
    i18n.translate('wazuh.ciscat.exclusions.excludeSelected', {
      defaultMessage: 'Exclude selected ({count})',
      values: { count },
    }),
  saveAndApply: () =>
    i18n.translate('wazuh.ciscat.exclusions.saveAndApply', {
      defaultMessage: 'Save and apply',
    }),
  apply: () =>
    i18n.translate('wazuh.ciscat.exclusions.apply', {
      defaultMessage: 'Apply',
    }),
  cannotReadBench: () =>
    i18n.translate('wazuh.ciscat.exclusions.cannotReadBench', {
      defaultMessage: 'Cannot read the benchmark sheet',
    }),
  unsavedChanges: () =>
    i18n.translate('wazuh.ciscat.exclusions.unsaved', {
      defaultMessage: ' · unsaved changes',
    }),

  // controls table
  selectControl: (rule: string) =>
    i18n.translate('wazuh.ciscat.controls.select', {
      defaultMessage: 'Select {rule}',
      values: { rule },
    }),
  columnCis: () =>
    i18n.translate('wazuh.ciscat.controls.cis', { defaultMessage: 'CIS' }),
  columnControl: () =>
    i18n.translate('wazuh.ciscat.controls.control', {
      defaultMessage: 'Control',
    }),
  manualHelp: () =>
    i18n.translate('wazuh.ciscat.controls.manualHelp', {
      defaultMessage:
        'Manual control: CIS-CAT does not assess it, so it is never scored',
    }),
  manual: () =>
    i18n.translate('wazuh.ciscat.controls.manual', {
      defaultMessage: 'manual',
    }),
  notInProfile: () =>
    i18n.translate('wazuh.ciscat.controls.notInProfile', {
      defaultMessage: 'not in profile',
    }),
  columnExcludedFor: () =>
    i18n.translate('wazuh.ciscat.controls.excludedFor', {
      defaultMessage: 'Excluded for',
    }),
  exclusionTooltip: (reason: string, ticket: string) =>
    i18n.translate('wazuh.ciscat.controls.exclusionTooltip', {
      defaultMessage: '{reason} · ticket {ticket}',
      values: {
        reason,
        ticket,
      },
    }),
  removeExclusion: () =>
    i18n.translate('wazuh.ciscat.controls.removeExclusion', {
      defaultMessage: 'Remove exclusion',
    }),
  excludeControl: (rule: string) =>
    i18n.translate('wazuh.ciscat.controls.exclude', {
      defaultMessage: 'Exclude {rule}',
      values: { rule },
    }),
  excludeTitle: () =>
    i18n.translate('wazuh.ciscat.controls.excludeTitle', {
      defaultMessage: 'Exclude…',
    }),

  // exclusion flyout
  scopeOs: () =>
    i18n.translate('wazuh.ciscat.flyout.scopeOs', {
      defaultMessage: 'All agents of this OS',
    }),
  scopeHost: () =>
    i18n.translate('wazuh.ciscat.flyout.scopeHost', {
      defaultMessage: 'Specific agents',
    }),
  scopeGroup: () =>
    i18n.translate('wazuh.ciscat.flyout.scopeGroup', {
      defaultMessage: 'Agent groups',
    }),
  scopeGlobal: () =>
    i18n.translate('wazuh.ciscat.flyout.scopeGlobal', {
      defaultMessage: 'Global (every OS with this number)',
    }),
  excludeRules: (what: string) =>
    i18n.translate('wazuh.ciscat.flyout.title', {
      defaultMessage: 'Exclude {what}',
      values: { what },
    }),
  controlsCount: (count: number) =>
    i18n.translate('wazuh.ciscat.flyout.controls', {
      defaultMessage: '{count} controls',
      values: { count },
    }),
  excludeFor: () =>
    i18n.translate('wazuh.ciscat.flyout.excludeFor', {
      defaultMessage: 'Exclude for',
    }),
  agents: () =>
    i18n.translate('wazuh.ciscat.flyout.agents', { defaultMessage: 'Agents' }),
  agentGroups: () =>
    i18n.translate('wazuh.ciscat.flyout.agentGroups', {
      defaultMessage: 'Agent groups',
    }),
  namesHelp: () =>
    i18n.translate('wazuh.ciscat.flyout.namesHelp', {
      defaultMessage: 'Pick from the list or type names (comma separated).',
    }),
  reason: () =>
    i18n.translate('wazuh.ciscat.flyout.reason', { defaultMessage: 'Reason' }),
  reasonHelp: () =>
    i18n.translate('wazuh.ciscat.flyout.reasonHelp', {
      defaultMessage: 'Kept for the audit trail.',
    }),
  ticket: () =>
    i18n.translate('wazuh.ciscat.flyout.ticket', { defaultMessage: 'Ticket' }),
  owner: () =>
    i18n.translate('wazuh.ciscat.flyout.owner', { defaultMessage: 'Owner' }),
  addExclusion: () =>
    i18n.translate('wazuh.ciscat.flyout.add', {
      defaultMessage: 'Add exclusion',
    }),

  // schedules
  scheduleNotSaved: () =>
    i18n.translate('wazuh.ciscat.schedule.notSaved', {
      defaultMessage: 'Schedule not saved',
    }),
  columnSchedule: () =>
    i18n.translate('wazuh.ciscat.schedule.schedule', {
      defaultMessage: 'Schedule',
    }),
  columnTargets: () =>
    i18n.translate('wazuh.ciscat.schedule.targets', {
      defaultMessage: 'Targets',
    }),
  columnWaves: () =>
    i18n.translate('wazuh.ciscat.schedule.waves', { defaultMessage: 'Waves' }),
  waves: (size: number, pause: number) =>
    i18n.translate('wazuh.ciscat.schedule.wavesValue', {
      defaultMessage: '{size} agents, {pause} min pause',
      values: {
        size,
        pause,
      },
    }),
  columnNextRun: () =>
    i18n.translate('wazuh.ciscat.schedule.nextRun', {
      defaultMessage: 'Next run',
    }),
  disabled: () =>
    i18n.translate('wazuh.ciscat.schedule.disabled', {
      defaultMessage: 'disabled',
    }),
  columnLastRun: () =>
    i18n.translate('wazuh.ciscat.schedule.lastRun', {
      defaultMessage: 'Last run',
    }),
  columnEnabled: () =>
    i18n.translate('wazuh.ciscat.schedule.enabled', {
      defaultMessage: 'Enabled',
    }),
  scheduleDisabled: () =>
    i18n.translate('wazuh.ciscat.schedule.disabledToast', {
      defaultMessage: 'Schedule disabled',
    }),
  scheduleEnabled: () =>
    i18n.translate('wazuh.ciscat.schedule.enabledToast', {
      defaultMessage: 'Schedule enabled',
    }),
  edit: () =>
    i18n.translate('wazuh.ciscat.schedule.edit', { defaultMessage: 'Edit' }),
  delete: () =>
    i18n.translate('wazuh.ciscat.schedule.delete', {
      defaultMessage: 'Delete',
    }),
  timeZone: (zone: string) =>
    i18n.translate('wazuh.ciscat.schedule.timeZone', {
      defaultMessage:
        // eslint-disable-next-line quotes -- the text has an apostrophe
        "Times are in the manager's time zone{zone}. Disconnected agents are " +
        'skipped and reported in the status.',
      values: { zone },
    }),
  runNow: () =>
    i18n.translate('wazuh.ciscat.schedule.runNow', {
      defaultMessage: 'Run now',
    }),
  newSchedule: () =>
    i18n.translate('wazuh.ciscat.schedule.new', {
      defaultMessage: 'New schedule',
    }),
  noSchedule: () =>
    i18n.translate('wazuh.ciscat.schedule.empty', {
      defaultMessage: 'No schedule yet: CIS-CAT runs only on demand.',
    }),
  scheduleSaved: () =>
    i18n.translate('wazuh.ciscat.schedule.saved', {
      defaultMessage: 'Schedule saved',
    }),
  runRequested: () =>
    i18n.translate('wazuh.ciscat.schedule.runRequested', {
      defaultMessage: 'Run requested',
    }),
  runStartsWithin: (minutes: number) =>
    i18n.translate('wazuh.ciscat.schedule.runStartsWithin', {
      defaultMessage: 'The manager starts it within {minutes} minutes.',
      values: { minutes },
    }),
  runNotRequested: () =>
    i18n.translate('wazuh.ciscat.schedule.runNotRequested', {
      defaultMessage: 'Run not requested',
    }),
  deleteTitle: () =>
    i18n.translate('wazuh.ciscat.schedule.deleteTitle', {
      defaultMessage: 'Delete this schedule?',
    }),
  scheduleDeleted: () =>
    i18n.translate('wazuh.ciscat.schedule.deleted', {
      defaultMessage: 'Schedule deleted',
    }),

  // schedule flyout
  runCiscatNow: () =>
    i18n.translate('wazuh.ciscat.job.runNowTitle', {
      defaultMessage: 'Run CIS-CAT now',
    }),
  editSchedule: () =>
    i18n.translate('wazuh.ciscat.job.editTitle', {
      defaultMessage: 'Edit schedule',
    }),
  name: () =>
    i18n.translate('wazuh.ciscat.job.name', { defaultMessage: 'Name' }),
  namePlaceholder: () =>
    i18n.translate('wazuh.ciscat.job.namePlaceholder', {
      defaultMessage: 'Month-end assessment',
    }),
  when: () =>
    i18n.translate('wazuh.ciscat.job.when', { defaultMessage: 'When' }),
  once: () =>
    i18n.translate('wazuh.ciscat.job.once', { defaultMessage: 'Once' }),
  everyMonth: () =>
    i18n.translate('wazuh.ciscat.job.everyMonth', {
      defaultMessage: 'Every month',
    }),
  everyWeek: () =>
    i18n.translate('wazuh.ciscat.job.everyWeek', {
      defaultMessage: 'Every week',
    }),
  date: () =>
    i18n.translate('wazuh.ciscat.job.date', { defaultMessage: 'Date' }),
  day: () => i18n.translate('wazuh.ciscat.job.day', { defaultMessage: 'Day' }),
  dayOfMonth: () =>
    i18n.translate('wazuh.ciscat.job.dayOfMonth', {
      defaultMessage: 'Day of the month',
    }),
  daysBeforeEnd: () =>
    i18n.translate('wazuh.ciscat.job.daysBeforeEnd', {
      defaultMessage: 'Days before the end of the month',
    }),
  dayFromEnd: () =>
    i18n.translate('wazuh.ciscat.job.dayFromEnd', {
      defaultMessage: 'Day from the end (1 = last day)',
    }),
  dayOfMonthHelp: () =>
    i18n.translate('wazuh.ciscat.job.dayOfMonthHelp', {
      defaultMessage: '1..31; months without that day use their last day',
    }),
  dayOfWeek: () =>
    i18n.translate('wazuh.ciscat.job.dayOfWeek', {
      defaultMessage: 'Day of the week',
    }),
  monday: () =>
    i18n.translate('wazuh.ciscat.job.monday', { defaultMessage: 'Monday' }),
  tuesday: () =>
    i18n.translate('wazuh.ciscat.job.tuesday', { defaultMessage: 'Tuesday' }),
  wednesday: () =>
    i18n.translate('wazuh.ciscat.job.wednesday', {
      defaultMessage: 'Wednesday',
    }),
  thursday: () =>
    i18n.translate('wazuh.ciscat.job.thursday', { defaultMessage: 'Thursday' }),
  friday: () =>
    i18n.translate('wazuh.ciscat.job.friday', { defaultMessage: 'Friday' }),
  saturday: () =>
    i18n.translate('wazuh.ciscat.job.saturday', { defaultMessage: 'Saturday' }),
  sunday: () =>
    i18n.translate('wazuh.ciscat.job.sunday', { defaultMessage: 'Sunday' }),
  time: () =>
    i18n.translate('wazuh.ciscat.job.time', { defaultMessage: 'Time' }),
  timeHelp: () =>
    i18n.translate('wazuh.ciscat.job.timeHelp', {
      // eslint-disable-next-line quotes -- the text has an apostrophe
      defaultMessage: "HH:MM, manager's local time",
    }),
  operatingSystems: () =>
    i18n.translate('wazuh.ciscat.job.operatingSystems', {
      defaultMessage: 'Operating systems',
    }),
  allActiveOs: () =>
    i18n.translate('wazuh.ciscat.job.allActiveOs', {
      defaultMessage: 'All active OS',
    }),
  agentsPerWave: () =>
    i18n.translate('wazuh.ciscat.job.agentsPerWave', {
      defaultMessage: 'Agents per wave',
    }),
  pauseBetweenWaves: () =>
    i18n.translate('wazuh.ciscat.job.pauseBetweenWaves', {
      defaultMessage: 'Pause between waves (minutes)',
    }),
  enabled: () =>
    i18n.translate('wazuh.ciscat.job.enabled', { defaultMessage: 'Enabled' }),

  // status
  running: () =>
    i18n.translate('wazuh.ciscat.status.running', {
      defaultMessage: 'Running',
    }),
  notRunning: (minutes: number) =>
    i18n.translate('wazuh.ciscat.status.notRunning', {
      defaultMessage: 'Not running (no tick for {minutes} minutes)',
      values: {
        minutes,
      },
    }),
  neverRan: () =>
    i18n.translate('wazuh.ciscat.status.neverRan', {
      defaultMessage: 'Never ran',
    }),
  scheduler: () =>
    i18n.translate('wazuh.ciscat.status.scheduler', {
      defaultMessage: 'Scheduler',
    }),
  state: () =>
    i18n.translate('wazuh.ciscat.status.state', { defaultMessage: 'State' }),
  lastTick: () =>
    i18n.translate('wazuh.ciscat.status.lastTick', {
      defaultMessage: 'Last tick',
    }),
  benchmarksPublished: () =>
    i18n.translate('wazuh.ciscat.status.benchmarksPublished', {
      defaultMessage: 'Benchmarks published',
    }),
  managerTimeZone: () =>
    i18n.translate('wazuh.ciscat.status.managerTimeZone', {
      defaultMessage: 'Manager time zone',
    }),
  pendingRequests: () =>
    i18n.translate('wazuh.ciscat.status.pendingRequests', {
      defaultMessage: 'Pending requests',
    }),
  pendingCount: (count: number) =>
    i18n.translate('wazuh.ciscat.status.pendingCount', {
      defaultMessage: '{count} (handled at the next tick)',
      values: { count },
    }),
  none: () =>
    i18n.translate('wazuh.ciscat.status.none', { defaultMessage: 'none' }),
  lastApply: () =>
    i18n.translate('wazuh.ciscat.status.lastApply', {
      defaultMessage: 'Last apply',
    }),
  result: () =>
    i18n.translate('wazuh.ciscat.status.result', { defaultMessage: 'Result' }),
  neverApplied: () =>
    i18n.translate('wazuh.ciscat.status.neverApplied', {
      defaultMessage: 'never applied from the dashboard',
    }),
  started: () =>
    i18n.translate('wazuh.ciscat.status.started', {
      defaultMessage: 'Started',
    }),
  finished: () =>
    i18n.translate('wazuh.ciscat.status.finished', {
      defaultMessage: 'Finished',
    }),
  bridgeVersion: () =>
    i18n.translate('wazuh.ciscat.status.bridgeVersion', {
      defaultMessage: 'Bridge version',
    }),
  notRunningTitle: () =>
    i18n.translate('wazuh.ciscat.status.notRunningTitle', {
      defaultMessage: 'The scheduler is not running',
    }),
  notRunningHelp: () =>
    i18n.translate('wazuh.ciscat.status.notRunningHelp', {
      defaultMessage:
        'Check the cron entry /etc/cron.d/ciscat-scheduler and ' +
        '/opt/ciscat/log/ciscat-scheduler.log on the manager. Saved changes ' +
        'and schedules wait until it runs again.',
    }),
  reportedByApply: () =>
    i18n.translate('wazuh.ciscat.status.reportedByApply', {
      defaultMessage: 'Reported by the last apply',
    }),
  policiesPerOs: () =>
    i18n.translate('wazuh.ciscat.status.policiesPerOs', {
      defaultMessage: 'Policies per OS',
    }),
  combinationsHelp: (group: string) =>
    i18n.translate('wazuh.ciscat.status.combinationsHelp', {
      defaultMessage:
        'Agents with the same agent or group exclusions share a combination ' +
        '(group {group}); "base" has none.',
      values: { group },
    }),
  columnOs: () =>
    i18n.translate('wazuh.ciscat.status.os', { defaultMessage: 'OS' }),
  columnAgents: () =>
    i18n.translate('wazuh.ciscat.status.agents', { defaultMessage: 'Agents' }),
  columnExclusions: () =>
    i18n.translate('wazuh.ciscat.status.exclusions', {
      defaultMessage: 'Exclusions',
    }),
  columnCombinations: () =>
    i18n.translate('wazuh.ciscat.status.combinations', {
      defaultMessage: 'Combinations',
    }),
  columnChecks: () =>
    i18n.translate('wazuh.ciscat.status.checks', {
      defaultMessage: 'Checks per combination',
    }),
  noApply: () =>
    i18n.translate('wazuh.ciscat.status.noApply', {
      defaultMessage: 'No apply yet',
    }),
  recentRuns: () =>
    i18n.translate('wazuh.ciscat.status.recentRuns', {
      defaultMessage: 'Recent runs',
    }),
  columnRun: () =>
    i18n.translate('wazuh.ciscat.status.run', { defaultMessage: 'Run' }),
  columnAgentsTriggered: () =>
    i18n.translate('wazuh.ciscat.status.agentsTriggered', {
      defaultMessage: 'Agents triggered',
    }),
  columnFailed: () =>
    i18n.translate('wazuh.ciscat.status.failed', { defaultMessage: 'Failed' }),
  columnSkipped: () =>
    i18n.translate('wazuh.ciscat.status.skipped', {
      defaultMessage: 'Skipped (disconnected)',
    }),
  noRun: () =>
    i18n.translate('wazuh.ciscat.status.noRun', {
      defaultMessage: 'No run yet',
    }),
};
