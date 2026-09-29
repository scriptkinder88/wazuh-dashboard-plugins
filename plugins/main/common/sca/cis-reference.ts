/*
 * CIS recommendation numbers for SCA checks.
 *
 * Two sources are supported:
 * - CIS-CAT Pro imports put the recommendation number at the start of the check
 *   title (for example "1.1.1 Ensure ..."). None of the policies shipped with
 *   Wazuh 4.x does this, so a numeric title prefix identifies an import.
 * - Wazuh native policies carry the number in the `cis` compliance mapping of
 *   the policy itself (for example `{ key: 'cis', value: '2.2.5' }` from the
 *   API, or `{ cis: '2.2.5' }` in indexed alerts).
 *
 * The family is the first level of the number ("2" for "2.2.5").
 */

export type CisReferenceSource = 'title' | 'compliance';

export interface CisReference {
  /** Full recommendation number, for example "1.1.1". */
  reference?: string;
  /** First level of the recommendation number, for example "1". */
  family?: string;
  /** Title without the recommendation number prefix. */
  title: string;
  source?: CisReferenceSource;
}

const REFERENCE_PATTERN = /^[0-9]+(\.[0-9]+){0,9}$/;
// At least two levels, so a title such as "2 users ..." is not taken as a number.
const TITLE_PREFIX_PATTERN = /^\s*([0-9]+(?:\.[0-9]+){1,9})\.?\s+(\S[\s\S]*)$/;
const CIS_COMPLIANCE_KEY = 'cis';

export const isCisReference = (value: unknown): value is string =>
  typeof value === 'string' && REFERENCE_PATTERN.test(value);

/** Numeric comparison: "1.2" sorts before "1.10". */
export const compareCisReferences = (a: string, b: string): number => {
  const left = a.split('.').map(Number);
  const right = b.split('.').map(Number);

  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    if (left[i] === undefined) {
      return -1;
    }
    if (right[i] === undefined) {
      return 1;
    }
    if (left[i] !== right[i]) {
      return left[i] - right[i];
    }
  }

  return 0;
};

const flattenValues = (value: unknown): string[] => {
  if (value === null || value === undefined) {
    return [];
  }
  if (Array.isArray(value)) {
    return value.flatMap(flattenValues);
  }
  if (typeof value === 'object') {
    return Object.values(value as object).flatMap(flattenValues);
  }
  return String(value)
    .split(/[,\s]+/)
    .map(item => item.trim())
    .filter(Boolean);
};

const collectComplianceValues = (compliance: unknown): unknown[] => {
  if (Array.isArray(compliance)) {
    return compliance
      .filter(
        item =>
          item &&
          typeof item === 'object' &&
          String(item.key).toLowerCase() === CIS_COMPLIANCE_KEY,
      )
      .map(item => item.value);
  }
  if (compliance && typeof compliance === 'object') {
    return Object.entries(compliance as object)
      .filter(([key]) => key.toLowerCase() === CIS_COMPLIANCE_KEY)
      .map(([, value]) => value);
  }
  return [];
};

/**
 * Recommendation number from the `cis` compliance mapping. When a check maps
 * to several numbers the lowest one is used, so the result does not depend on
 * row order; a range ("2.8-2.9") uses its start.
 */
export const cisReferenceFromCompliance = (
  compliance: unknown,
): string | undefined => {
  const references = flattenValues(collectComplianceValues(compliance))
    .map(value => value.split('-')[0].trim())
    .filter(isCisReference)
    .sort(compareCisReferences);

  return references[0];
};

export const cisReferenceFromTitle = (
  title: unknown,
): { reference: string; title: string } | undefined => {
  if (typeof title !== 'string') {
    return undefined;
  }
  const match = TITLE_PREFIX_PATTERN.exec(title);

  return match ? { reference: match[1], title: match[2].trim() } : undefined;
};

export const resolveCisReference = (check: {
  title?: unknown;
  compliance?: unknown;
}): CisReference => {
  const title = typeof check?.title === 'string' ? check.title : '';
  const fromTitle = cisReferenceFromTitle(title);

  if (fromTitle) {
    return {
      reference: fromTitle.reference,
      family: fromTitle.reference.split('.')[0],
      title: fromTitle.title,
      source: 'title',
    };
  }

  const reference = cisReferenceFromCompliance(check?.compliance);

  if (!reference) {
    return { title };
  }

  return {
    reference,
    family: reference.split('.')[0],
    title,
    source: 'compliance',
  };
};
