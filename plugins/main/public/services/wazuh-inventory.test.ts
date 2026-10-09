/* eslint-disable camelcase */ // Wazuh API field names
import { WzRequest } from '../react-services';
import {
  API_MAX_LIMIT,
  fetchAgentNames,
  fetchAllAgents,
  fetchGroupNames,
} from './wazuh-inventory';

jest.mock('../react-services', () => ({
  WzRequest: { apiReq: jest.fn() },
}));

const apiReq = WzRequest.apiReq as jest.Mock;
const respond = (items: object[]) =>
  apiReq.mockResolvedValue({ data: { data: { affected_items: items } } });

beforeEach(() => apiReq.mockReset());

describe('wazuh inventory', () => {
  it('reads every agent but the manager with the selected fields', async () => {
    respond([{ id: '001' }]);
    await expect(fetchAllAgents(['id', 'os.platform'])).resolves.toEqual([
      { id: '001' },
    ]);
    expect(apiReq).toHaveBeenCalledWith('GET', '/agents', {
      params: { select: 'id,os.platform', q: 'id!=000', limit: API_MAX_LIMIT },
    });
  });

  it('returns sorted, non-empty agent and group names', async () => {
    respond([{ name: 'web-02' }, { name: '' }, { name: 'db-01' }]);
    await expect(fetchAgentNames()).resolves.toEqual(['db-01', 'web-02']);
    respond([{ name: 'z' }, { name: 'a' }]);
    await expect(fetchGroupNames()).resolves.toEqual(['a', 'z']);
    expect(apiReq).toHaveBeenLastCalledWith('GET', '/groups', {
      params: { limit: API_MAX_LIMIT },
    });
  });

  it('propagates a rejected request', async () => {
    apiReq.mockRejectedValue(new Error('forbidden'));
    await expect(fetchGroupNames()).rejects.toThrow('forbidden');
  });
});
