/* eslint-disable camelcase -- fields of SCA states documents */
import {
  getScaCisColumnValue,
  SCA_CIS_COLUMN_ID,
  scaCisColumn,
  tableColumns,
} from './index';

describe('SCA inventory CIS column', () => {
  it('shows the CIS number and the family title of the policy', () => {
    expect(
      getScaCisColumnValue({
        policy: { id: 'cis_rhel9_linux' },
        check: { name: '5.2.1 Ensure permissions on sshd_config are set' },
      }),
    ).toBe('5.2.1 - Access, Authentication and Authorization');
  });

  it('prefers the family title carried by the check', () => {
    expect(
      getScaCisColumnValue({
        policy: { id: 'cis_rhel9_linux' },
        check: {
          name: '1.1.1 Ensure cramfs is disabled',
          compliance: { cis_family: ['1 Initial Setup (bridge)'] },
        },
      }),
    ).toBe('1.1.1 - Initial Setup (bridge)');
  });

  it('shows only the number when the family title is unknown', () => {
    expect(
      getScaCisColumnValue({
        policy: { id: 'custom_policy' },
        check: { name: '2.3 Ensure something' },
      }),
    ).toBe('2.3');
  });

  it("shows '-' when the check has no CIS number", () => {
    expect(
      getScaCisColumnValue({
        policy: { id: 'cis_rhel9_linux' },
        check: {
          name: 'Ensure cramfs is disabled',
          compliance: { pci_dss: ['2.2'] },
        },
      }),
    ).toBe('-');
    expect(getScaCisColumnValue(undefined)).toBe('-');
    expect(getScaCisColumnValue({})).toBe('-');
  });

  it('is a computed, non sortable column rendered from the row', () => {
    expect(tableColumns).toContain(scaCisColumn);
    expect(scaCisColumn).toMatchObject({
      id: SCA_CIS_COLUMN_ID,
      displayAsText: 'CIS',
      computed: true,
      isSortable: false,
    });
    expect(
      scaCisColumn.render?.(undefined, {
        policy: { id: 'cis_debian11' },
        check: { name: '4.1.1 Ensure auditd is installed' },
      }),
    ).toBe('4.1.1 - Logging and Auditing');
  });
});
