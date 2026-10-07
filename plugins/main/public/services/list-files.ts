/*
 * CDB list files under etc/lists that hold encoded records, read and written
 * with the same calls as the CDB lists editor.
 */
import { WzRequest } from '../react-services';
// eslint-disable-next-line max-len
import { ResourcesHandler } from '../controllers/management/components/management/common/resources-handler';
import { ListRecords, parseList, renderList } from '../../common/encoded-list';

const lists = new ResourcesHandler('lists');

export interface LoadedList {
  records: ListRecords;
  errors: string[];
  /** Raw content as read, to detect a concurrent change before writing. */
  raw: string;
  exists: boolean;
}

/** Most list files a name search returns. */
const LIST_SEARCH_LIMIT = 500;

/** Names of the list files matching `search`. */
export const existingLists = async (search: string): Promise<Set<string>> => {
  // /lists/files returns names only; /lists would return every list's items
  const response = await WzRequest.apiReq('GET', '/lists/files', {
    params: { search, limit: LIST_SEARCH_LIMIT },
  });
  const items = response?.data?.data?.affected_items || [];
  return new Set(
    items.map((item: { filename?: string }) => item.filename || ''),
  );
};

/** A list file, or an empty one when it does not exist in `existing`. */
export const readList = async (
  name: string,
  existing: Set<string>,
): Promise<LoadedList> => {
  if (!existing.has(name)) {
    return { records: {}, errors: [], raw: '', exists: false };
  }
  const raw = String((await lists.getFileContent(name)) || '');
  return { ...parseList(raw), raw, exists: true };
};

export class ConcurrentChangeError extends Error {}

/**
 * Writes a list file. When `expectedRaw` is given, the file is read again
 * first and the write is refused if someone else changed it meanwhile.
 */
export const writeList = async (
  name: string,
  records: ListRecords,
  expectedRaw?: string,
) => {
  if (expectedRaw !== undefined) {
    const current = await readList(name, await existingLists(name));
    if (current.raw !== expectedRaw) {
      throw new ConcurrentChangeError(
        `${name} was changed by someone else: reload before saving`,
      );
    }
  }
  const content = renderList(records);
  // An empty list file is rejected by the API: keep a placeholder record.
  await lists.updateFile(
    name,
    content || renderList({ _empty: { v: 1 } }),
    true,
  );
};
