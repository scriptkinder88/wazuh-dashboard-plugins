import {
  cisFamilyTitleFromCompliance,
  cisReferenceFromCompliance,
  cisReferenceFromTitle,
  compareCisReferences,
  resolveCisReference,
} from './cis-reference';

describe('CIS recommendation numbers', () => {
  it('reads the number from the Wazuh API compliance list', () => {
    expect(
      cisReferenceFromCompliance([
        { key: 'cis_csc_v8', value: '5.2' },
        { key: 'cis', value: '2.2.5' },
      ]),
    ).toBe('2.2.5');
  });

  it('reads the number from the indexed alert compliance object', () => {
    expect(
      cisReferenceFromCompliance({ cis: '1.1.1', pci_dss_v4: '2.2.1,2.2.2' }),
    ).toBe('1.1.1');
    expect(cisReferenceFromCompliance({ cis: { 0: '4.1', 1: '3.2' } })).toBe(
      '3.2',
    );
  });

  it('uses the lowest number and the start of a range', () => {
    expect(
      cisReferenceFromCompliance([
        { key: 'CIS', value: '2.3' },
        { key: 'cis', value: '1.10' },
      ]),
    ).toBe('1.10');
    expect(
      cisReferenceFromCompliance([{ key: 'cis', value: '4.1, 3.2' }]),
    ).toBe('3.2');
    expect(cisReferenceFromCompliance([{ key: 'cis', value: '2.8-2.9' }])).toBe(
      '2.8',
    );
  });

  it('ignores invalid or unrelated values', () => {
    for (const bad of [
      undefined,
      null,
      'x',
      [{ key: 'cis', value: 'abc' }],
      [{ key: 'pci_dss', value: '2.2' }],
      [null, { key: 1, value: '2' }],
      { cis_csc_v8: '5.2' },
    ]) {
      expect(cisReferenceFromCompliance(bad)).toBeUndefined();
    }
  });

  it('reads a CIS-CAT Pro number from the title prefix', () => {
    expect(
      cisReferenceFromTitle('1.1.1 Ensure mounting of cramfs is disabled'),
    ).toEqual({
      reference: '1.1.1',
      title: 'Ensure mounting of cramfs is disabled',
    });
    expect(cisReferenceFromTitle('18.10.4. Ensure x')).toEqual({
      reference: '18.10.4',
      title: 'Ensure x',
    });
    expect(cisReferenceFromTitle('Ensure 1.2 is set')).toBeUndefined();
    expect(cisReferenceFromTitle('2 users are allowed')).toBeUndefined();
    expect(cisReferenceFromTitle('1.1.1')).toBeUndefined();
  });

  it('prefers the title prefix, then the compliance mapping', () => {
    expect(
      resolveCisReference({
        title: '5.2.1 Ensure sshd is configured',
        compliance: [{ key: 'cis', value: '5.3' }],
      }),
    ).toEqual({
      reference: '5.2.1',
      family: '5',
      title: 'Ensure sshd is configured',
      source: 'title',
    });
    expect(
      resolveCisReference({
        title: 'Ensure sshd is configured',
        compliance: [{ key: 'cis', value: '18.10.4' }],
      }),
    ).toEqual({
      reference: '18.10.4',
      family: '18',
      title: 'Ensure sshd is configured',
      source: 'compliance',
    });
    expect(resolveCisReference({ title: 'Web check' })).toEqual({
      title: 'Web check',
    });
  });

  it('reads the family title carried by the check', () => {
    // Wazuh API list and indexed alert object.
    expect(
      cisFamilyTitleFromCompliance(
        [
          { key: 'cis_csc_v8', value: '5.2' },
          {
            key: 'cis_family',
            value: '4 Access, Authentication and Authorization',
          },
        ],
        '4',
      ),
    ).toBe('Access, Authentication and Authorization');
    expect(
      cisFamilyTitleFromCompliance(
        { cis_family: ['18 - Admin  Templates'] },
        '18',
      ),
    ).toBe('Admin Templates');
    // Only the check's own family, and only well-formed values.
    expect(
      cisFamilyTitleFromCompliance({ cis_family: '1 Initial Setup' }, '2'),
    ).toBeUndefined();
    expect(
      cisFamilyTitleFromCompliance({ cis_family: 'Initial Setup' }, '1'),
    ).toBeUndefined();
    expect(cisFamilyTitleFromCompliance(undefined, '1')).toBeUndefined();
    expect(
      resolveCisReference({
        title: '1.1.1 Ensure mounting is disabled',
        compliance: [
          { key: 'cis_csc_v8', value: '4.8' },
          { key: 'cis_family', value: '1 Initial Setup' },
        ],
      }),
    ).toEqual({
      reference: '1.1.1',
      family: '1',
      familyTitle: 'Initial Setup',
      title: 'Ensure mounting is disabled',
      source: 'title',
    });
  });

  it('sorts numbers numerically', () => {
    expect(
      ['1.10', '1.2', '10.1', '2', '1.2.1'].sort(compareCisReferences),
    ).toEqual(['1.2', '1.2.1', '1.10', '2', '10.1']);
  });
});
