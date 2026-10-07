/* eslint-disable camelcase */ // Wazuh API field names
import { TextDecoder, TextEncoder } from 'util';
import { WzRequest } from '../react-services';
import { ConcurrentChangeError, readList, writeList } from './list-files';
import { renderList } from '../../common/encoded-list';

Object.assign(globalThis, { TextEncoder, TextDecoder });

const mockFiles: Record<string, string> = {};
const mockUpdate = jest.fn();

jest.mock('../react-services', () => ({
  WzRequest: { apiReq: jest.fn() },
}));

jest.mock(
  '../controllers/management/components/management/common/resources-handler',
  () => ({
    ResourcesHandler: jest.fn().mockImplementation(() => ({
      getFileContent: (name: string) => Promise.resolve(mockFiles[name]),
      updateFile: (...args: unknown[]) => mockUpdate(...args),
    })),
  }),
);

beforeEach(() => {
  Object.keys(mockFiles).forEach(name => delete mockFiles[name]);
  mockUpdate.mockReset().mockResolvedValue(undefined);
  (WzRequest.apiReq as jest.Mock).mockImplementation(
    (_method: string, _path: string, { params }) =>
      Promise.resolve({
        data: {
          data: {
            affected_items: Object.keys(mockFiles)
              .filter(name => name.includes(params.search))
              .map(filename => ({ filename })),
          },
        },
      }),
  );
});

describe('list files', () => {
  it('reads a list that exists and an empty one that does not', async () => {
    mockFiles['fim-history'] = renderList({ a: { v: 1 } });
    await expect(
      readList('fim-history', new Set(['fim-history'])),
    ).resolves.toEqual(
      expect.objectContaining({ records: { a: { v: 1 } }, exists: true }),
    );
    await expect(readList('other', new Set())).resolves.toEqual(
      expect.objectContaining({ records: {}, exists: false, raw: '' }),
    );
  });

  it('writes a list of any name that did not change meanwhile', async () => {
    mockFiles['fim-history'] = renderList({ a: { v: 1 } });
    await writeList('fim-history', { b: { v: 1 } }, mockFiles['fim-history']);
    expect(mockUpdate).toHaveBeenCalledWith(
      'fim-history',
      renderList({ b: { v: 1 } }),
      true,
    );
  });

  it('refuses to overwrite a list changed by someone else', async () => {
    mockFiles['fim-history'] = renderList({ a: { v: 2 } });
    await expect(
      writeList('fim-history', {}, renderList({ a: { v: 1 } })),
    ).rejects.toThrow(ConcurrentChangeError);
    expect(mockUpdate).not.toHaveBeenCalled();
  });

  it('keeps a placeholder record in an emptied list', async () => {
    await writeList('ciscat-requests', {});
    expect(mockUpdate).toHaveBeenCalledWith(
      'ciscat-requests',
      renderList({ _empty: { v: 1 } }),
      true,
    );
  });
});
