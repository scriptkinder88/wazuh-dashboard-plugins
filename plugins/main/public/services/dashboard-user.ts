import { getHttp } from '../kibana-services';

/** Dashboard user, recorded in the audit fields; empty when unknown. */
export const fetchCurrentUserName = async (): Promise<string> => {
  try {
    const account = await getHttp().get('/api/v1/configuration/account');
    return String(account?.data?.user_name || '');
  } catch {
    return '';
  }
};
