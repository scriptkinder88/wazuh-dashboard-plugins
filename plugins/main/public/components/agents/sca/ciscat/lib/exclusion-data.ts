/*
 * Exclusions and benchmark groups as edited in the exclusions panel, and
 * saving them to the ciscat-* lists.
 */
/* eslint-disable camelcase */ // record fields are the snake_case wire format
import {
  CISCAT_LISTS,
  newRequestKey,
  validateExclusion,
  validateTarget,
} from '../../../../../../common/ciscat/store';
import { KeyedExclusions } from './composer';
import { addRequest, writeList } from './lists-api';
import type { CiscatData } from '../ciscat-management';

export const validExclusions = (records: CiscatData['exclusions']['records']) =>
  Object.entries(records).reduce((acc, [key, rec]) => {
    if (!key.startsWith('_')) {
      try {
        acc[key] = validateExclusion(rec);
      } catch {
        // invalid records are reported by the manager, not edited here
      }
    }
    return acc;
  }, {} as KeyedExclusions);

/** Group each OS applies to: chosen here (ciscat-targets) or the master's default. */
export const savedTargets = (data: CiscatData): Record<string, string> =>
  Object.fromEntries(
    Object.keys(data.oskeys).map(k => {
      const rec = data.targets.records[k];
      return [
        k,
        String((rec && rec.group) || data.oskeys[k].group || `os-${k}`),
      ];
    }),
  );

/** Benchmark name and version, e.g. "Red Hat Enterprise Linux 9 v2.0.0". */
export const osTitle = (data: CiscatData, key: string) => {
  const os = data.oskeys[key];
  const title = String(os.title || key);
  return os.version && !title.includes(`v${os.version}`)
    ? `${title} v${os.version}`
    : title;
};

/** The exclusions were saved, but the benchmark groups or the apply request were not. */
export class PartialSaveError extends Error {}

/**
 * Writes the exclusions, then the benchmark groups that changed, then (with
 * `apply`) a request for the manager to regenerate the policies.
 */
export const saveExclusions = async ({
  data,
  draft,
  targets,
  user,
  apply,
}: {
  data: CiscatData;
  draft: KeyedExclusions;
  targets: Record<string, string>;
  user: string;
  apply: boolean;
}) => {
  await writeList(CISCAT_LISTS.exclusions, draft, data.exclusions.raw);
  try {
    const saved = savedTargets(data);
    if (Object.keys(targets).some(k => targets[k] !== saved[k])) {
      const records = { ...data.targets.records };
      delete records._empty;
      Object.entries(targets).forEach(([k, group]) => {
        if (group !== saved[k]) {
          records[k] = {
            ...validateTarget({
              group,
              updated_by: user,
              updated_at: new Date().toISOString(),
            }),
          };
        }
      });
      await writeList(CISCAT_LISTS.targets, records, data.targets.raw);
    }
    if (apply) {
      await addRequest(
        newRequestKey(),
        {
          action: 'apply',
          requested_by: user,
          requested_at: new Date().toISOString(),
        },
        (data.status.requests?.processed as string[]) || [],
      );
    }
  } catch (error) {
    throw new PartialSaveError((error as Error)?.message || String(error));
  }
};
