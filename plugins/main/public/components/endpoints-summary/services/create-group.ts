import IApiResponse from '../../../react-services/interfaces/api-response.interface';
import { WzRequest } from '../../../react-services/wz-request';

export const createGroupService = async (groupId: string) =>
  (await WzRequest.apiReq('POST', '/groups', {
    group_id: groupId, // eslint-disable-line camelcase
  })) as IApiResponse<string>;
