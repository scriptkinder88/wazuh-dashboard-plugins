/*
 * "Test the path": how many entries of the FIM inventory of a few target
 * agents are under the path of the rule being written.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { EuiText } from '@elastic/eui';
import { isExclusionKind, isRegistryKind } from './lib/agent-conf';
import { AgentInfo } from './lib/plan';
import { inventoryPrefix, rulePaths } from './lib/path-checks';
import { PathTestResult, testPathOnAgents } from './lib/fim-api';
import { FormState } from './lib/rule-form';
import { messages } from './messages';

/** Agents the path test runs on: the chosen servers, then agents of the groups. */
const TEST_AGENTS = 5;

const testOutcome = (r: PathTestResult) => {
  if (r.error) {
    return messages.testCannotRead(r.error);
  }
  if (r.files) {
    return messages.testEntries(`${r.files}${r.more ? '+' : ''}`);
  }
  return r.more ? messages.testNoneSampled() : messages.testNone();
};

export const PathTest = ({
  results,
  prefix,
}: {
  results: PathTestResult[];
  prefix: string;
}) => (
  <EuiText size='xs' data-test-subj='fim-path-test'>
    <p>
      {messages.testUnder()} <code>{prefix}</code>:
    </p>
    <ul>
      {results.map(r => (
        <li key={r.agent.id}>
          {r.agent.name} ({r.agent.id}
          {r.agent.status !== 'active' ? `, ${r.agent.status}` : ''}):{' '}
          {testOutcome(r)}
          {r.lastScan
            ? messages.testLastScan(new Date(r.lastScan).toLocaleString())
            : ''}
        </li>
      ))}
    </ul>
  </EuiText>
);

/** The agents to test, the path prefix, and the state of the last test. */
export const usePathTest = (
  agents: AgentInfo[],
  form: Pick<FormState, 'kind' | 'path' | 'sregex' | 'groups' | 'hostIds'>,
) => {
  // path test: the chosen servers first, then agents of the chosen groups, active first
  const testAgents = useMemo(() => {
    const byId = new Map(agents.map(a => [a.id, a]));
    const hosts = form.hostIds
      .map(id => byId.get(id))
      .filter(Boolean) as AgentInfo[];
    const members = agents
      .filter(
        a =>
          !form.hostIds.includes(a.id) &&
          a.groups.some(g => form.groups.includes(g)),
      )
      .sort(
        (a, b) => Number(b.status === 'active') - Number(a.status === 'active'),
      );
    return [...hosts, ...members].slice(0, TEST_AGENTS);
  }, [agents, form.groups, form.hostIds]);
  const testPrefix = inventoryPrefix(rulePaths(form.kind, form.path)[0] || '');
  const canTest =
    !!testPrefix &&
    testAgents.length > 0 &&
    !isRegistryKind(form.kind) &&
    !(isExclusionKind(form.kind) && form.sregex);
  const [test, setTest] = useState<{
    prefix: string;
    results?: PathTestResult[];
  }>();
  useEffect(() => setTest(undefined), [testPrefix, testAgents]);
  const onAgents =
    testAgents.length === 1 ? messages.testOnAgent : messages.testOnAgents;
  const testLabel = testAgents.length
    ? onAgents(testAgents.length)
    : messages.testChooseFirst();
  const runTest = async () => {
    setTest({ prefix: testPrefix });
    const results = await testPathOnAgents(testPrefix, testAgents);
    // ignore the results if the path or the agents changed meanwhile
    setTest(current =>
      current?.prefix === testPrefix && !current.results
        ? { prefix: testPrefix, results }
        : current,
    );
  };

  return { testAgents, testPrefix, canTest, test, testLabel, runTest };
};
