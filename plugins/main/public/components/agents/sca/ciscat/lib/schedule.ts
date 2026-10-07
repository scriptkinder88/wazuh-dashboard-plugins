/*
 * Schedules as read from ciscat-schedule, and how their state is shown.
 */
import {
  Job,
  ListRecords,
  validateJob,
} from '../../../../../../common/ciscat/store';

/** Health color of a scheduler state. */
export const STATE_COLOR: Record<string, string> = {
  ok: 'success',
  error: 'danger',
  running: 'primary',
  starting: 'primary',
};

export const validJobs = (records: ListRecords) =>
  Object.entries(records).reduce((acc, [key, rec]) => {
    if (!key.startsWith('_')) {
      try {
        acc[key] = validateJob(rec);
      } catch {
        // invalid jobs are reported by the manager
      }
    }
    return acc;
  }, {} as Record<string, Job>);

export const formatDate = (date?: Date) => (date ? date.toLocaleString() : '—');
