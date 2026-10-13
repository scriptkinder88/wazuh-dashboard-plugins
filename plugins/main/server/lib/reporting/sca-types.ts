/*
 * Shapes of the SCA events read from the alerts index for the SCA report, and
 * of the search client used to read them.
 */
/* eslint-disable camelcase */ // index document fields

/** OpenSearch query DSL, as built by the dashboard search bar. */
export type OpenSearchQuery = Record<string, unknown>;

export interface BoolQuery {
  bool: {
    must?: unknown[];
    filter: unknown[];
    [clause: string]: unknown;
  };
}

export interface ScaCheck {
  id?: string | number;
  title?: string;
  result?: string;
  status?: string;
  reason?: string;
  rationale?: string;
  remediation?: string;
  description?: string;
  compliance?: unknown;
}

export interface ScaEventData {
  scan_id?: string | number;
  policy?: string;
  policy_id?: string;
  name?: string;
  total_checks?: number | string;
  passed?: number | string;
  failed?: number | string;
  invalid?: number | string;
  score?: number | string | null;
  check?: ScaCheck;
}

/** An SCA event of the alerts index (only the fields the report reads). */
export interface ScaDocument {
  timestamp?: string;
  agent?: { id?: string; name?: string; ip?: string };
  data?: { sca?: ScaEventData };
}

export type CompositeKey = Record<string, string | number>;

interface TopHit {
  latest?: { hits?: { hits?: Array<{ _source?: ScaDocument }> } };
}

export interface TermsBucket extends TopHit {
  key?: string;
}

export interface CompositeBucket extends TopHit {
  key?: CompositeKey;
}

export interface Aggregation<B> {
  buckets?: B[];
  after_key?: CompositeKey;
}

type Aggregations = Record<string, Aggregation<TermsBucket | CompositeBucket>>;

export interface ScaSearchResponse {
  body?: { aggregations?: Aggregations };
  aggregations?: Aggregations;
}

/** The part of the route handler context the SCA report uses. */
export interface ScaSearchContext {
  core: {
    opensearch: {
      client: {
        asCurrentUser: {
          search: (
            params: Record<string, unknown>,
          ) => Promise<ScaSearchResponse>;
        };
      };
    };
  };
}

/** Composite key of a check bucket: agent, policy and check. */
export interface ScaCheckKey {
  agent_id?: string | number;
  policy?: string | number;
  check_id?: string | number;
}

export interface ScaCheckEntry {
  key: ScaCheckKey;
  source: ScaDocument;
}

/** An agent of the report, from its latest SCA event. */
export interface ScaAgentInfo {
  id?: string;
  name?: string;
  ip?: string;
  timestamp?: string;
}

/** Latest scan summary of a policy on an agent. */
export interface ScaPolicySummary {
  agentId: string;
  policyKey: string;
  policy: string;
  totalChecks: number | null;
  passed: number;
  failed: number;
  invalid: number;
  score: number | null;
  scanId?: string | number;
  timestamp?: string;
}
