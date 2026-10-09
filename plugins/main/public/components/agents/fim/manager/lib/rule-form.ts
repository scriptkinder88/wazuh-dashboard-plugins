/*
 * State of the rule form, and the attributes and block filter it writes.
 */
/* eslint-disable camelcase */ // attribute names are the agent.conf ones
import {
  BlockFilter,
  FimRule,
  KIND_ATTRS,
  RuleKind,
  isMonitorKind,
  isRegistryKind,
} from './agent-conf';
import { RuleRow } from './plan';

export type Platform = 'any' | 'Linux' | 'Windows' | 'keep';
export type Mode = 'scheduled' | 'realtime' | 'whodata';

export interface FormState {
  kind: RuleKind;
  path: string;
  platform: Platform;
  mode: Mode;
  reportChanges: boolean;
  recursion: string;
  restrict: string;
  tags: string;
  sregex: boolean;
  arch: string;
  groups: string[];
  hostIds: string[];
  reason: string;
  ticket: string;
  owner: string;
}

export const platformOf = (filter: BlockFilter): Platform => {
  const keys = Object.keys(filter);
  if (!keys.length) {
    return 'any';
  }
  if (keys.length === 1 && (filter.os === 'Linux' || filter.os === 'Windows')) {
    return filter.os;
  }
  return 'keep';
};

export const modeOf = (attrs: Record<string, string>): Mode => {
  if (attrs.whodata === 'yes') {
    return 'whodata';
  }
  return attrs.realtime === 'yes' ? 'realtime' : 'scheduled';
};

export const initialState = (row?: RuleRow): FormState => {
  const rule = row?.rule;
  const attrs = rule?.attrs || {};
  return {
    kind: rule?.kind || 'directories',
    path: rule?.path || '',
    platform: rule ? platformOf(rule.filter) : 'any',
    mode: modeOf(attrs),
    reportChanges: attrs.report_changes === 'yes',
    recursion: attrs.recursion_level || '',
    restrict: attrs.restrict || '',
    tags: attrs.tags || '',
    sregex: attrs.type === 'sregex',
    arch: attrs.arch || '',
    groups: row?.groups || [],
    hostIds: row?.hostIds || [],
    reason: rule?.meta?.reason || '',
    ticket: rule?.meta?.ticket || '',
    owner: rule?.meta?.owner || '',
  };
};

/** Attributes written for the form, plus any the form does not manage. */
export const buildAttrs = (form: FormState, original?: FimRule) => {
  const managed = KIND_ATTRS[form.kind];
  const attrs: Record<string, string> = {};
  Object.entries(original?.attrs || {}).forEach(([k, v]) => {
    if (!managed.includes(k)) {
      attrs[k] = v;
    }
  });
  const set = (k: string, v: string | boolean | undefined) => {
    if (v && managed.includes(k)) {
      attrs[k] = v === true ? 'yes' : String(v);
    }
  };
  if (form.kind === 'directories') {
    set('realtime', form.mode === 'realtime');
    set('whodata', form.mode === 'whodata');
  }
  if (isMonitorKind(form.kind)) {
    set('report_changes', form.reportChanges);
    set('recursion_level', form.recursion.trim());
    set('restrict', form.restrict.trim());
    set('tags', form.tags.trim());
  } else {
    set('type', form.sregex && 'sregex');
  }
  if (isRegistryKind(form.kind)) {
    set('arch', form.arch);
  }
  if (form.kind === 'directories' && original?.attrs.follow_symbolic_link) {
    attrs.follow_symbolic_link = original.attrs.follow_symbolic_link;
  }
  return attrs;
};

export const buildFilter = (
  form: FormState,
  original?: FimRule,
): BlockFilter => {
  if (form.platform === 'keep') {
    return original?.filter || {};
  }
  return form.platform === 'any' ? {} : { os: form.platform };
};
