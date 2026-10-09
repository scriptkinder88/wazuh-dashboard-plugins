/*
 * Hints shown in the rule form, each with the fixes it offers.
 */
import React from 'react';
import { EuiButtonEmpty, EuiCallOut, EuiText } from '@elastic/eui';
import { Hint, HintFix } from './lib/path-checks';
import { messages } from './messages';

export const HintList = ({
  hints,
  onFix,
  testSubj,
}: {
  hints: Hint[];
  onFix: (fix: HintFix) => void;
  testSubj: string;
}) =>
  hints.length ? (
    <EuiCallOut
      size='s'
      color='warning'
      iconType='alert'
      title={
        hints.length === 1
          ? messages.checkHint()
          : messages.checkHints(hints.length)
      }
      data-test-subj={testSubj}
    >
      {hints.map(h => (
        <div key={h.message} style={{ marginBottom: 4 }}>
          <EuiText size='xs'>
            <p>{h.message}</p>
          </EuiText>
          {(h.fixes || []).map(f => (
            <EuiButtonEmpty
              key={f.label}
              size='xs'
              flush='left'
              onClick={() => onFix(f)}
              data-test-subj='fim-rule-fix'
            >
              {f.label}
            </EuiButtonEmpty>
          ))}
        </div>
      ))}
    </EuiCallOut>
  ) : null;
