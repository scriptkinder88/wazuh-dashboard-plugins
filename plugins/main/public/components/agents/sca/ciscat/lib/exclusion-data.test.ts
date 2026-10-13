/* eslint-disable camelcase */ // record fields are the snake_case wire format
import { webcrypto } from 'crypto';
import { TextDecoder, TextEncoder } from 'util';
import {
  PartialSaveError,
  osTitle,
  saveExclusions,
  savedTargets,
  validExclusions,
} from './exclusion-data';
import { addRequest, writeList } from './lists-api';
import type { CiscatData } from '../ciscat-management';

Object.assign(globalThis, { TextEncoder, TextDecoder });
if (!globalThis.crypto?.subtle) {
  Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
}

jest.mock('./lists-api', () => ({
  addRequest: jest.fn(),
  writeList: jest.fn(),
}));

const list = (records = {}, raw = '') => ({
  records,
  errors: [],
  raw,
  exists: true,
});

const data = (): CiscatData => ({
  oskeys: {
    rhel7: { v: 1, title: 'Red Hat Enterprise Linux 7', version: '4.0.0' },
    win: { v: 1, title: 'Windows v2.0.0', version: '2.0.0', group: 'os-win' },
  },
  status: { requests: { processed: ['r1'] } },
  exclusions: list({}, 'exclusions-raw'),
  schedule: list(),
  requests: list(),
  targets: list({ rhel7: { v: 1, group: 'app-sap' } }, 'targets-raw'),
  history: {},
});

beforeEach(() => {
  (writeList as jest.Mock).mockReset().mockResolvedValue(undefined);
  (addRequest as jest.Mock).mockReset().mockResolvedValue(undefined);
});

describe('exclusion data', () => {
  it('keeps the valid exclusions only', () => {
    const valid = {
      os_key: 'rhel7',
      scope: 'os',
      rule: '1.1.1',
      reason: 'storage',
    };
    expect(
      Object.keys(
        validExclusions({
          _empty: { v: 1 },
          good: valid,
          bad: { ...valid, rule: 'x' },
        }),
      ),
    ).toEqual(['good']);
  });

  it('reads the group of each OS and its title with the version', () => {
    expect(savedTargets(data())).toEqual({ rhel7: 'app-sap', win: 'os-win' });
    expect(osTitle(data(), 'rhel7')).toBe('Red Hat Enterprise Linux 7 v4.0.0');
    expect(osTitle(data(), 'win')).toBe('Windows v2.0.0');
  });

  it('writes the exclusions, the changed groups, then the apply request', async () => {
    await saveExclusions({
      data: data(),
      draft: {},
      targets: { rhel7: 'app-sap', win: 'os-win-2019' },
      user: 'alice',
      apply: true,
    });
    const writes = (writeList as jest.Mock).mock.calls;
    expect(writes.map(([name, , raw]) => [name, raw])).toEqual([
      ['ciscat-exclusions', 'exclusions-raw'],
      ['ciscat-targets', 'targets-raw'],
    ]);
    expect(writes[1][1]).toEqual({
      rhel7: { v: 1, group: 'app-sap' },
      win: expect.objectContaining({
        group: 'os-win-2019',
        updated_by: 'alice',
      }),
    });
    expect(addRequest).toHaveBeenCalledWith(
      expect.stringMatching(/^r\d+/),
      expect.objectContaining({ action: 'apply', requested_by: 'alice' }),
      ['r1'],
    );
  });

  it('does not write unchanged groups nor request an apply on save', async () => {
    await saveExclusions({
      data: data(),
      draft: {},
      targets: savedTargets(data()),
      user: 'alice',
      apply: false,
    });
    expect((writeList as jest.Mock).mock.calls.map(([name]) => name)).toEqual([
      'ciscat-exclusions',
    ]);
    expect(addRequest).not.toHaveBeenCalled();
  });

  it('tells a failure after the exclusions were written from one before', async () => {
    (addRequest as jest.Mock).mockRejectedValue(new Error('denied'));
    await expect(
      saveExclusions({
        data: data(),
        draft: {},
        targets: {},
        user: 'alice',
        apply: true,
      }),
    ).rejects.toEqual(new PartialSaveError('denied'));

    (writeList as jest.Mock).mockRejectedValueOnce(new Error('changed'));
    const failure = saveExclusions({
      data: data(),
      draft: {},
      targets: {},
      user: 'alice',
      apply: true,
    });
    await expect(failure).rejects.toThrow('changed');
    await expect(failure).rejects.not.toBeInstanceOf(PartialSaveError);
  });
});
