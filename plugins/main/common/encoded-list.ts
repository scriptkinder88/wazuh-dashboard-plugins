/*
 * Records kept in Wazuh CDB list files. Wazuh only accepts list values
 * without ':' and '"', so every value is compact JSON (sorted keys) encoded
 * as unpadded base64url, one "key:value" line per record.
 */

export type ListRecord = Record<string, unknown>;
export type ListRecords = Record<string, ListRecord>;

export class EncodedListError extends Error {}

const KEY_RE = /^[A-Za-z0-9._-]{1,128}$/;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;

const sortKeys = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value && typeof value === 'object') {
    const obj = value as ListRecord;
    return Object.keys(obj)
      .sort()
      .reduce((acc, key) => {
        acc[key] = sortKeys(obj[key]);
        return acc;
      }, {} as ListRecord);
  }
  return value;
};

const bytesToBinary = (bytes: Uint8Array) => {
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return out;
};

export const encodeRecord = (obj: object): string => {
  const bytes = new TextEncoder().encode(JSON.stringify(sortKeys(obj)));
  return btoa(bytesToBinary(bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
};

export const decodeRecord = (value: string): ListRecord => {
  if (!B64URL_RE.test(value || '')) {
    throw new EncodedListError('value is not base64url');
  }
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
  const obj = JSON.parse(
    new TextDecoder('utf-8', { fatal: true }).decode(bytes),
  );
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new EncodedListError('value is not a JSON object');
  }
  return obj;
};

export const parseList = (
  text: string,
): { records: ListRecords; errors: string[] } => {
  const records: ListRecords = {};
  const errors: string[] = [];
  (text || '').split(/\r?\n/).forEach((line, index) => {
    if (!line.trim()) {
      return;
    }
    const sep = line.indexOf(':');
    const key = sep < 0 ? '' : line.slice(0, sep);
    if (!KEY_RE.test(key)) {
      errors.push(`line ${index + 1}: invalid key`);
      return;
    }
    try {
      records[key] = decodeRecord(line.slice(sep + 1).trim());
    } catch (error) {
      errors.push(`line ${index + 1}: ${(error as Error).message}`);
    }
  });
  return { records, errors };
};

export const renderList = (records: ListRecords): string => {
  const keys = Object.keys(records).sort();
  for (const key of keys) {
    if (!KEY_RE.test(key)) {
      throw new EncodedListError(`invalid key: ${key}`);
    }
  }
  return keys.map(key => `${key}:${encodeRecord(records[key])}\n`).join('');
};
