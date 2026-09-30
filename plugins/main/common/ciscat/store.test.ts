import { webcrypto } from 'crypto';
import vectors from './contract-vectors.json';
import {
  StoreError,
  benchListName,
  decodeRecord,
  encodeRecord,
  exclusionKey,
  newJobKey,
  newRequestKey,
  parseList,
  renderList,
  validateExclusion,
  validateJob,
} from './store';

// Wazuh 4.14 framework/wazuh/core/cdb_list.py validate_cdb_list
const WAZUH_CDB_LINE =
  /(?:^"([\w\-: ]+?)"|^[^:"\s]+):(?:"([\w\-: ]*?)"$|[^:"]*$)/;

beforeAll(() => {
  // jsdom/older node environments may not expose Web Crypto
  if (!globalThis.crypto?.subtle) {
    Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
  }
});

describe('CIS-CAT store contract (shared vectors with ciscat_store.py)', () => {
  it('normalizes, keys and encodes exclusions like the master', async () => {
    const normalized = vectors.exclusions.map(v => validateExclusion(v.input));
    const keys = await Promise.all(normalized.map(exclusionKey));
    vectors.exclusions.forEach((v, i) => {
      expect(normalized[i]).toEqual(v.normalized);
      expect(keys[i]).toBe(v.key);
      expect(encodeRecord(normalized[i])).toBe(v.encoded);
      expect(decodeRecord(v.encoded)).toEqual(v.normalized);
    });
  });

  it('normalizes jobs like the master', () => {
    for (const v of vectors.jobs) {
      expect(validateJob(v.input)).toEqual(v.normalized);
    }
  });

  it('rejects the records the master rejects', () => {
    for (const rec of vectors.invalid_exclusions) {
      expect(() => validateExclusion(rec)).toThrow(StoreError);
    }
    for (const rec of vectors.invalid_jobs) {
      expect(() => validateJob(rec)).toThrow(StoreError);
    }
  });
});

describe('CIS-CAT list files', () => {
  it('renders lines that pass Wazuh list validation and parse back', () => {
    const records = {
      e1: { t: 'Ensure "x": 24 | a,b è', n: 1 },
      '1.1.1.1': { t: 'x', p: ['L1_Server'] },
    };
    const text = renderList(records);
    for (const line of text.trim().split('\n')) {
      expect(line).toMatch(WAZUH_CDB_LINE);
    }
    expect(parseList(text)).toEqual({ records, errors: [] });
  });

  it('reports bad lines and keeps the good ones', () => {
    const good = encodeRecord({ a: 1 });
    const { records, errors } = parseList(
      `k1:${good}\n\nbad line\nk2:not base64!\nk3:${encodeRecord({ b: 2 })}`,
    );
    expect(records).toEqual({ k1: { a: 1 }, k3: { b: 2 } });
    expect(errors).toHaveLength(2);
  });

  it('refuses unsafe names and keys', () => {
    expect(() => benchListName('../x')).toThrow(StoreError);
    expect(benchListName('rhel7')).toBe('ciscat-bench-rhel7');
    expect(() => renderList({ 'a b': {} })).toThrow(StoreError);
  });

  it('creates keys in the documented shapes', () => {
    expect(newJobKey()).toMatch(/^j[0-9a-f]{12}$/);
    expect(newRequestKey(1700000000000)).toMatch(/^r1700000000000[0-9a-f]{4}$/);
  });
});
