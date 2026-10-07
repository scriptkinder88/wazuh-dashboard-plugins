/*
 * FIM rules inside a group's agent.conf.
 *
 * agent.conf is a list of <agent_config> blocks (optionally filtered by name,
 * os or profile) whose <syscheck> sections hold the rules managed here:
 * <directories>, <ignore>, <nodiff>, <windows_registry> and <registry_ignore>.
 * Edits are spliced into the original text, so everything else in the file
 * (other modules, comments, formatting) is kept byte for byte.
 *
 * Each rule written by the dashboard is preceded by a comment carrying its
 * audit fields: <!-- wz-fim <base64 JSON> -->. Standard base64 is used because
 * an XML comment must not contain "--".
 */
/* eslint-disable camelcase */ // element and attribute names of agent.conf

export const RULE_KINDS = [
  'directories',
  'ignore',
  'nodiff',
  'windows_registry',
  'registry_ignore',
] as const;
export type RuleKind = (typeof RULE_KINDS)[number];

export const KIND_LABELS: Record<RuleKind, string> = {
  directories: 'Monitor path',
  ignore: 'Ignore path',
  nodiff: 'No diff',
  windows_registry: 'Monitor registry key',
  registry_ignore: 'Ignore registry key',
};

/** Attributes the form can set, per kind (imported rules may carry others). */
export const KIND_ATTRS: Record<RuleKind, string[]> = {
  directories: [
    'realtime',
    'whodata',
    'report_changes',
    'recursion_level',
    'restrict',
    'tags',
    'follow_symbolic_link',
  ],
  ignore: ['type'],
  nodiff: ['type'],
  windows_registry: [
    'arch',
    'report_changes',
    'recursion_level',
    'restrict',
    'tags',
  ],
  registry_ignore: ['type', 'arch'],
};

export type BlockFilter = Record<string, string>;

export interface RuleMeta {
  reason: string;
  ticket: string;
  owner: string;
  by: string;
  at: string;
}

export interface FimRule {
  kind: RuleKind;
  path: string;
  attrs: Record<string, string>;
  /** Attributes of the enclosing <agent_config> (name, os, profile). */
  filter: BlockFilter;
  meta?: RuleMeta;
}

export interface LocatedRule extends FimRule {
  /** Text range removed when the rule is deleted (meta comment included). */
  range: [number, number];
}

export class AgentConfError extends Error {}

interface XmlNode {
  name: string;
  attrs: Record<string, string>;
  start: number;
  end: number;
  innerStart: number;
  innerEnd: number;
  children: XmlNode[];
  text: string;
  /** Start of the wz-fim comment right before this element, if any. */
  metaStart?: number;
  meta?: string;
}

const META_PREFIX = 'wz-fim ';
const ATTR_RE = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
const NAME_RE = /^[A-Za-z_][\w.-]*/;

// --- parsing ------------------------------------------------------------------

const parseAttrs = (source: string): Record<string, string> => {
  const attrs: Record<string, string> = {};
  ATTR_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ATTR_RE.exec(source))) {
    attrs[m[1]] = m[2] !== undefined ? m[2] : m[3];
  }
  return attrs;
};

/** Top-level elements of an XML fragment (agent.conf has several roots). */
const parseXml = (text: string): XmlNode[] => {
  const roots: XmlNode[] = [];
  const stack: XmlNode[] = [];
  let lastComment: { start: number; end: number; body: string } | undefined;
  let i = 0;
  const fail = (message: string) => {
    const line = text.slice(0, i).split('\n').length;
    throw new AgentConfError(`agent.conf line ${line}: ${message}`);
  };
  const append = (node: XmlNode) => {
    if (stack.length) {
      stack[stack.length - 1].children.push(node);
    } else {
      roots.push(node);
    }
  };
  while (i < text.length) {
    const lt = text.indexOf('<', i);
    if (lt < 0) {
      if (stack.length && text.slice(i).trim()) {
        stack[stack.length - 1].text += text.slice(i);
      }
      break;
    }
    if (stack.length) {
      stack[stack.length - 1].text += text.slice(i, lt);
    }
    i = lt;
    if (text.startsWith('<!--', i)) {
      const close = text.indexOf('-->', i + 4);
      if (close < 0) {
        fail('unterminated comment');
      }
      lastComment = {
        start: i,
        end: close + 3,
        body: text.slice(i + 4, close),
      };
      i = close + 3;
      continue;
    }
    if (text.startsWith('<?', i) || text.startsWith('<!', i)) {
      const close = text.startsWith('<![CDATA[', i)
        ? text.indexOf(']]>', i)
        : text.indexOf('>', i);
      if (close < 0) {
        fail('unterminated declaration');
      }
      i = close + (text.startsWith('<![CDATA[', i) ? 3 : 1);
      continue;
    }
    const gt = text.indexOf('>', i);
    if (gt < 0) {
      fail('unterminated tag');
    }
    if (text[i + 1] === '/') {
      const name = text.slice(i + 2, gt).trim();
      const open = stack.pop();
      if (!open || open.name !== name) {
        fail(`unexpected </${name}>`);
      }
      open!.innerEnd = i;
      open!.end = gt + 1;
      open!.text = open!.text.trim();
      i = gt + 1;
      continue;
    }
    const body = text.slice(i + 1, gt);
    const selfClosing = body.endsWith('/');
    const name = (body.match(NAME_RE) || [''])[0];
    if (!name) {
      fail('invalid tag');
    }
    const node: XmlNode = {
      name,
      attrs: parseAttrs(body.slice(name.length)),
      start: i,
      end: gt + 1,
      innerStart: gt + 1,
      innerEnd: gt + 1,
      children: [],
      text: '',
    };
    if (
      lastComment &&
      lastComment.body.trim().startsWith(META_PREFIX) &&
      !text.slice(lastComment.end, i).trim()
    ) {
      node.metaStart = lastComment.start;
      node.meta = lastComment.body.trim().slice(META_PREFIX.length).trim();
    }
    lastComment = undefined;
    append(node);
    if (!selfClosing) {
      stack.push(node);
    }
    i = gt + 1;
  }
  if (stack.length) {
    fail(`<${stack[stack.length - 1].name}> is not closed`);
  }
  return roots;
};

// --- meta comment ---------------------------------------------------------------

const toBase64 = (value: string) => {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  bytes.forEach(b => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
};

const fromBase64 = (value: string) =>
  new TextDecoder('utf-8', { fatal: true }).decode(
    Uint8Array.from(atob(value), c => c.charCodeAt(0)),
  );

export const encodeMeta = (meta: RuleMeta) =>
  toBase64(
    JSON.stringify({
      at: meta.at,
      by: meta.by,
      owner: meta.owner,
      reason: meta.reason,
      ticket: meta.ticket,
    }),
  );

export const decodeMeta = (value: string): RuleMeta | undefined => {
  try {
    const obj = JSON.parse(fromBase64(value));
    const str = (k: string) => (typeof obj?.[k] === 'string' ? obj[k] : '');
    return {
      reason: str('reason'),
      ticket: str('ticket'),
      owner: str('owner'),
      by: str('by'),
      at: str('at'),
    };
  } catch {
    return undefined;
  }
};

// --- rules ----------------------------------------------------------------------

const lineStart = (text: string, pos: number) => {
  const nl = text.lastIndexOf('\n', pos - 1);
  return text.slice(nl + 1, pos).trim() ? pos : nl + 1;
};

const lineEnd = (text: string, pos: number) => {
  const nl = text.indexOf('\n', pos);
  const end = nl < 0 ? text.length : nl;
  return text.slice(pos, end).trim() ? pos : nl < 0 ? end : nl + 1;
};

const isRuleKind = (name: string): name is RuleKind =>
  (RULE_KINDS as readonly string[]).includes(name);

/** Every FIM rule of the file, in document order. */
export const parseRules = (text: string): LocatedRule[] => {
  const rules: LocatedRule[] = [];
  parseXml(text || '')
    .filter(node => node.name === 'agent_config')
    .forEach(block => {
      block.children
        .filter(node => node.name === 'syscheck')
        .forEach(section => {
          section.children
            .filter(node => isRuleKind(node.name))
            .forEach(node => {
              const from = node.metaStart ?? node.start;
              rules.push({
                kind: node.name as RuleKind,
                path: node.text,
                attrs: node.attrs,
                filter: block.attrs,
                meta: node.meta ? decodeMeta(node.meta) : undefined,
                range: [lineStart(text, from), lineEnd(text, node.end)],
              });
            });
        });
    });
  return rules;
};

const sortedEntries = (obj: Record<string, string>) =>
  Object.keys(obj)
    .sort()
    .map(k => [k, obj[k]]);

/** Identity of a rule: same kind, path, attributes and block filter. */
export const ruleKey = (
  rule: Pick<FimRule, 'kind' | 'path' | 'attrs' | 'filter'>,
) =>
  JSON.stringify([
    rule.kind,
    rule.path.trim(),
    sortedEntries(rule.attrs),
    sortedEntries(rule.filter),
  ]);

/** Same target (kind, path and filter) regardless of options. */
export const targetKey = (rule: Pick<FimRule, 'kind' | 'path' | 'filter'>) =>
  JSON.stringify([rule.kind, rule.path.trim(), sortedEntries(rule.filter)]);

/*
 * Values are written and read as they are, without XML entities: the agents
 * parse agent.conf with the Wazuh XML reader, which does not decode entities
 * (a path written "R&amp;D" would be monitored literally as "R&amp;D"), and
 * the Wazuh server API escapes a bare "&" itself when it validates the file.
 * Only the characters that would end the value are refused.
 */
const FORBIDDEN_IN_TEXT = /[<>\r\n]/;
const FORBIDDEN_IN_ATTR = /[<>"\r\n]/;

/** Problems that prevent writing the rule; empty when valid. */
export const validateRule = (rule: FimRule): string[] => {
  const errors: string[] = [];
  if (!isRuleKind(rule.kind)) {
    errors.push(`unknown rule type ${rule.kind}`);
  }
  const path = (rule.path || '').trim();
  if (!path) {
    errors.push('the path is required');
  } else if (FORBIDDEN_IN_TEXT.test(path)) {
    errors.push('the path cannot contain < > or line breaks');
  } else if (path.length > 4096) {
    errors.push('the path is too long');
  }
  for (const [k, v] of Object.entries({ ...rule.attrs, ...rule.filter })) {
    if (!/^[A-Za-z_][\w.-]*$/.test(k) || FORBIDDEN_IN_ATTR.test(v)) {
      errors.push(`invalid attribute ${k}`);
    }
  }
  const level = rule.attrs.recursion_level;
  if (level !== undefined && !/^(\d{1,3})$/.test(level)) {
    errors.push('recursion level must be a number');
  } else if (level !== undefined && Number(level) > 320) {
    errors.push('recursion level must be 320 or less');
  }
  if (rule.attrs.tags && !/^[\w.,-]+$/.test(rule.attrs.tags)) {
    errors.push('tags: letters, digits, "_", ".", "-" separated by commas');
  }
  if (rule.meta && !rule.meta.reason.trim()) {
    errors.push('the reason is required');
  }
  return errors;
};

const attrText = (attrs: Record<string, string>) =>
  sortedEntries(attrs)
    .map(([k, v]) => ` ${k}="${v}"`)
    .join('');

export const ruleElement = (rule: FimRule) =>
  `<${rule.kind}${attrText(rule.attrs)}>${rule.path.trim()}</${rule.kind}>`;

const ruleLines = (rule: FimRule) => [
  ...(rule.meta ? [`<!-- ${META_PREFIX}${encodeMeta(rule.meta)} -->`] : []),
  ruleElement(rule),
];

const sameFilter = (a: BlockFilter, b: BlockFilter) =>
  JSON.stringify(sortedEntries(a)) === JSON.stringify(sortedEntries(b));

const indentOf = (text: string, pos: number) => {
  const start = text.lastIndexOf('\n', pos - 1) + 1;
  const prefix = text.slice(start, pos);
  return /^\s*$/.test(prefix) ? prefix : '';
};

/** Inserts lines before the closing tag of `node`, one level deeper. */
const insertBeforeClose = (text: string, node: XmlNode, lines: string[]) => {
  const closeIndent = indentOf(text, node.innerEnd);
  const indent = closeIndent + '  ';
  const start = text.lastIndexOf('\n', node.innerEnd - 1) + 1;
  const body = lines.map(l => `${indent}${l}\n`).join('');
  if (!text.slice(start, node.innerEnd).trim()) {
    // The closing tag is on its own line: insert whole lines before it.
    return text.slice(0, start) + body + text.slice(start);
  }
  return (
    text.slice(0, node.innerEnd) +
    '\n' +
    body +
    closeIndent +
    text.slice(node.innerEnd)
  );
};

const addRules = (text: string, rules: FimRule[]): string => {
  let out = text;
  rules.forEach(rule => {
    const blocks = parseXml(out).filter(n => n.name === 'agent_config');
    const block = blocks.find(b => sameFilter(b.attrs, rule.filter));
    if (!block) {
      let sep = '\n\n';
      if (!out || out.endsWith('\n\n')) {
        sep = '';
      } else if (out.endsWith('\n')) {
        sep = '\n';
      }
      out += [
        `${sep}<agent_config${attrText(rule.filter)}>`,
        '  <syscheck>',
        ...ruleLines(rule).map(l => `    ${l}`),
        '  </syscheck>',
        '</agent_config>\n',
      ].join('\n');
      return;
    }
    const section = block.children.find(n => n.name === 'syscheck');
    if (section) {
      out = insertBeforeClose(out, section, ruleLines(rule));
      return;
    }
    out = insertBeforeClose(out, block, [
      '<syscheck>',
      ...ruleLines(rule).map(l => `  ${l}`),
      '</syscheck>',
    ]);
  });
  return out;
};

const removeRanges = (text: string, ranges: Array<[number, number]>) =>
  [...ranges]
    .sort((a, b) => b[0] - a[0])
    .reduce((acc, [from, to]) => acc.slice(0, from) + acc.slice(to), text);

/**
 * Drops <syscheck> sections left without content, then filtered
 * <agent_config> blocks left empty. Neither changes the configuration.
 */
const dropEmpty = (text: string): string => {
  const roots = parseXml(text);
  const ranges: Array<[number, number]> = [];
  roots
    .filter(n => n.name === 'agent_config')
    .forEach(block => {
      const empties = block.children.filter(
        n =>
          n.name === 'syscheck' && !text.slice(n.innerStart, n.innerEnd).trim(),
      );
      const rest = block.children.filter(n => !empties.includes(n));
      const innerLeft = removeRanges(
        text.slice(block.innerStart, block.innerEnd),
        empties.map(n => [
          n.start - block.innerStart,
          n.end - block.innerStart,
        ]),
      );
      if (
        !rest.length &&
        !innerLeft.trim() &&
        Object.keys(block.attrs).length
      ) {
        // Also drop the blank line that separated the block from the previous one.
        const from = lineStart(text, block.start);
        const blank = from >= 2 && text.slice(from - 2, from) === '\n\n';
        ranges.push([blank ? from - 1 : from, lineEnd(text, block.end)]);
      } else {
        empties.forEach(n =>
          ranges.push([lineStart(text, n.start), lineEnd(text, n.end)]),
        );
      }
    });
  return removeRanges(text, ranges);
};

export interface AgentConfEdit {
  /** ruleKey() of the rules to delete (every occurrence). */
  remove?: string[];
  add?: FimRule[];
}

/** The text of `rule` in place of `slot`, with the slot's indentation. */
const replacement = (text: string, slot: LocatedRule, rule: FimRule) => {
  const [from, to] = slot.range;
  if (text[to - 1] !== '\n') {
    return ruleLines(rule).join(' ');
  }
  const indent = (text.slice(from).match(/^[ \t]*/) || [''])[0];
  return ruleLines(rule)
    .map(l => `${indent}${l}\n`)
    .join('');
};

/**
 * The file with the edit applied; the rest of the text is unchanged. An added
 * rule that targets the same kind, path and filter as a removed one takes its
 * place, so changing a rule's options does not move it.
 */
export const editAgentConf = (text: string, edit: AgentConfEdit): string => {
  const remove = new Set(edit.remove || []);
  const add = edit.add || [];
  add.forEach(rule => {
    const errors = validateRule(rule);
    if (errors.length) {
      throw new AgentConfError(errors.join('; '));
    }
  });
  let out = text || '';
  const pending: FimRule[] = [];
  if (remove.size) {
    const slots = parseRules(out).filter(rule => remove.has(ruleKey(rule)));
    const filled = new Map<LocatedRule, FimRule>();
    add.forEach(rule => {
      const slot = slots.find(
        s => !filled.has(s) && targetKey(s) === targetKey(rule),
      );
      if (slot) {
        filled.set(slot, rule);
      } else {
        pending.push(rule);
      }
    });
    out = [...slots]
      .sort((a, b) => b.range[0] - a.range[0])
      .reduce((acc, slot) => {
        const rule = filled.get(slot);
        const [from, to] = slot.range;
        return (
          acc.slice(0, from) +
          (rule ? replacement(acc, slot, rule) : '') +
          acc.slice(to)
        );
      }, out);
    if (slots.length > filled.size) {
      out = dropEmpty(out);
    }
  } else {
    pending.push(...add);
  }
  const present = new Set(parseRules(out).map(ruleKey));
  out = addRules(
    out,
    pending.filter(rule => !present.has(ruleKey(rule))),
  );
  // Fail here rather than on the manager if the result is not well formed.
  parseXml(out);
  return out;
};
