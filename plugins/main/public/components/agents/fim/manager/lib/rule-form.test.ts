/* eslint-disable camelcase */ // agent.conf attribute names
import { FimRule } from './agent-conf';
import { RuleRow } from './plan';
import {
  buildAttrs,
  buildFilter,
  initialState,
  modeOf,
  platformOf,
} from './rule-form';

const imported: FimRule = {
  kind: 'directories',
  path: '/etc/app',
  attrs: {
    whodata: 'yes',
    report_changes: 'yes',
    check_sha256sum: 'no',
    follow_symbolic_link: 'yes',
  },
  filter: { os: 'Linux', profile: 'web' },
};

const row = (rule: FimRule): RuleRow => ({
  key: 'k',
  rule,
  groups: ['web'],
  hostIds: ['001'],
});

describe('rule form', () => {
  it('reads the platform and mode of a rule', () => {
    expect(platformOf({})).toBe('any');
    expect(platformOf({ os: 'Windows' })).toBe('Windows');
    expect(platformOf({ os: 'Linux', profile: 'web' })).toBe('keep');
    expect(modeOf({ whodata: 'yes', realtime: 'yes' })).toBe('whodata');
    expect(modeOf({ realtime: 'yes' })).toBe('realtime');
    expect(modeOf({})).toBe('scheduled');
  });

  it('starts from the rule being changed', () => {
    expect(initialState(row(imported))).toEqual(
      expect.objectContaining({
        kind: 'directories',
        path: '/etc/app',
        platform: 'keep',
        mode: 'whodata',
        reportChanges: true,
        groups: ['web'],
        hostIds: ['001'],
      }),
    );
    expect(initialState()).toEqual(
      expect.objectContaining({ kind: 'directories', platform: 'any' }),
    );
  });

  it('writes the options of the form and keeps the others', () => {
    const form = {
      ...initialState(row(imported)),
      mode: 'realtime' as const,
      reportChanges: false,
      recursion: ' 3 ',
    };
    expect(buildAttrs(form, imported)).toEqual({
      realtime: 'yes',
      recursion_level: '3',
      check_sha256sum: 'no',
      follow_symbolic_link: 'yes',
    });
  });

  it('writes type="sregex" only for exclusions', () => {
    const form = {
      ...initialState(),
      kind: 'ignore' as const,
      sregex: true,
      reportChanges: true,
    };
    expect(buildAttrs(form)).toEqual({ type: 'sregex' });
  });

  it('keeps an imported filter or writes the platform', () => {
    const form = initialState(row(imported));
    expect(buildFilter(form, imported)).toEqual({
      os: 'Linux',
      profile: 'web',
    });
    expect(buildFilter({ ...form, platform: 'Windows' }, imported)).toEqual({
      os: 'Windows',
    });
    expect(buildFilter({ ...form, platform: 'any' }, imported)).toEqual({});
  });
});
