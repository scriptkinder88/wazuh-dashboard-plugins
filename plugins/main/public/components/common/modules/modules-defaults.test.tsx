import { TAB_VIEW_ID_DASHBOARD } from '../../../../common/constants';
import { ModulesDefaults } from './modules-defaults';

describe('ModulesDefaults SCA reporting', () => {
  it('exposes the Generate report action on the SCA dashboard tab', () => {
    const dashboardTab = ModulesDefaults.sca.tabs.find(
      ({ id }) => id === TAB_VIEW_ID_DASHBOARD,
    );

    expect(dashboardTab).toBeDefined();
    expect(dashboardTab?.buttons).toHaveLength(2);
    expect(dashboardTab?.buttons?.[1]).toEqual(
      expect.objectContaining({
        component: expect.anything(),
        condition: expect.any(Function),
      }),
    );
  });
});
