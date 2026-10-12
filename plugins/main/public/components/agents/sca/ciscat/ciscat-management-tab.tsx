/*
 * The CIS-CAT tab, shown only to users who can read the CDB lists it uses.
 */
import { withUserAuthorizationPrompt } from '../../../common/hocs';
import { CiscatManagement } from './ciscat-management';
import { CISCAT_READ_PERMISSIONS } from './lib/permissions';

export const CiscatManagementTab = withUserAuthorizationPrompt(
  CISCAT_READ_PERMISSIONS,
)(CiscatManagement);
