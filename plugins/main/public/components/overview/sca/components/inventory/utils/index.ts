import { commonColumns } from '../../../../common/data-grid-columns';
import { resolveCisReference } from '../../../../../../../common/sca/cis-reference';
import { getCisFamilyTitle } from '../../../../../../../common/compliance-requirements/cis-families';
import { tDataGridColumn } from '../../../../../common/data-grid/types';

export const SCA_CIS_COLUMN_ID = 'cis';

/**
 * CIS recommendation number of an SCA states document plus the title of its
 * benchmark family, e.g. "1.1.1 - Initial Setup". The number comes from the
 * `check.name` prefix (CIS-CAT bridge policies); the family title from the
 * check itself or from the CIS family index of the policy. Returns '-' when
 * the check has no CIS number.
 */
interface ScaStateRow {
  policy?: { id?: string };
  check?: { name?: string; compliance?: unknown };
}

export const getScaCisColumnValue = (rowItem?: ScaStateRow): string => {
  const check = rowItem?.check || {};
  const cis = resolveCisReference({
    title: check.name,
    compliance: check.compliance,
  });

  if (!cis.reference) {
    return '-';
  }

  const familyTitle =
    cis.familyTitle || getCisFamilyTitle(rowItem?.policy?.id, cis.family);

  return familyTitle ? `${cis.reference} - ${familyTitle}` : cis.reference;
};

export const scaCisColumn: tDataGridColumn = {
  id: SCA_CIS_COLUMN_ID,
  displayAsText: 'CIS',
  initialWidth: 220,
  computed: true,
  isSortable: false,
  render: (_value, rowItem) => getScaCisColumnValue(rowItem),
};

export const tableColumns = [
  commonColumns['wazuh.agent.name'],
  { id: 'policy.name' },
  { id: 'check.id', initialWidth: 100 },
  scaCisColumn,
  { id: 'check.name' },
  { id: 'check.result', initialWidth: 130 },
];

export const managedFilters = [
  {
    type: 'multiSelect',
    key: 'policy.name',
    placeholder: 'Policy',
  },
  {
    type: 'multiSelect',
    key: 'check.name',
    placeholder: 'Check',
  },
];
