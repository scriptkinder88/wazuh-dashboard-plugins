/*
 * Records the dashboard keeps in the Wazuh indexer for its own features (FIM rules history,
 * CIS-CAT bridge data). Wazuh 5.0 has no CDB lists, which held this data on 4.x.
 *
 * One hidden index per collection; a record is { kind, key, data } plus who changed it and when.
 */

export const DASHBOARD_STORE_COLLECTIONS = {
  'fim-history': 'wz-dashboard-store-fim-history',
  ciscat: 'wz-dashboard-store-ciscat',
} as const;

export type DashboardStoreCollection = keyof typeof DASHBOARD_STORE_COLLECTIONS;

export const DASHBOARD_STORE_ID_RE = /^[A-Za-z0-9._:-]{1,200}$/;
export const DASHBOARD_STORE_KIND_RE = /^[A-Za-z0-9._-]{1,64}$/;

export interface DashboardStoreRecord<T = Record<string, unknown>> {
  id: string;
  kind: string;
  key: string;
  data: T;
  updated_by: string;
  updated_at: string;
  /** Optimistic concurrency: pass both back to update the record only if unchanged. */
  seqNo?: number;
  primaryTerm?: number;
}

export const isDashboardStoreCollection = (
  name: string,
): name is DashboardStoreCollection =>
  Object.prototype.hasOwnProperty.call(DASHBOARD_STORE_COLLECTIONS, name);
