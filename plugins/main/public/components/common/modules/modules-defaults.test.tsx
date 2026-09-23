import { ModulesDefaults } from './modules-defaults';

describe('ModulesDefaults SCA reporting', () => {
  it('exposes the Generate report action on the SCA dashboard tab', () => {
    const dashboardTab = ModulesDefaults.sca.tabs.find(
      ({ id }) => id === 'dashboard',
    );

    expect(dashboardTab).toBeDefined();
    expect(dashboardTab?.buttons).toHaveLength(2);
  });
});
