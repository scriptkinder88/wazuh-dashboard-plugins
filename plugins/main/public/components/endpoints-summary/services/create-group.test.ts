import { createGroupService } from './create-group';
import { groupNameError } from './group-name';
import { WzRequest } from '../../../react-services/wz-request';

jest.mock('../../../react-services/wz-request', () => ({
  WzRequest: {
    apiReq: jest.fn(),
  },
}));

describe('createGroupService', () => {
  it('creates the group with the Wazuh server API', async () => {
    (WzRequest.apiReq as jest.Mock).mockResolvedValue({ data: { error: 0 } });
    await createGroupService('web-prod');
    expect(WzRequest.apiReq).toHaveBeenCalledWith('POST', '/groups', {
      group_id: 'web-prod', // eslint-disable-line camelcase
    });
  });
});

describe('groupNameError', () => {
  it('accepts the names the Wazuh server API accepts', () => {
    expect(groupNameError('web-prod_01.eu')).toBeUndefined();
  });

  it('rejects invalid, reserved, too long and existing names', () => {
    expect(groupNameError('web prod')).toMatch(/letters, numbers/);
    expect(groupNameError('web/prod')).toMatch(/letters, numbers/);
    expect(groupNameError('..')).toMatch(/cannot be/);
    expect(groupNameError('a'.repeat(129))).toMatch(/at most 128/);
    expect(groupNameError('default', ['default'])).toMatch(/already exists/);
  });
});
