/*
 * The FIM rules tab, shown only to users who can read the groups, the agents
 * and the history list.
 */
import { withUserAuthorizationPrompt } from '../../../common/hocs';
import { FimManagement } from './fim-management';
import { FIM_READ_PERMISSIONS } from './lib/permissions';

export const FimManagementTab =
  withUserAuthorizationPrompt(FIM_READ_PERMISSIONS)(FimManagement);
