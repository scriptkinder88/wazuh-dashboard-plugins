import { cisFamiliesFile, getCisFamilyTitle } from './cis-families';

describe('CIS family titles', () => {
  it('returns the title of a family for a known policy', () => {
    expect(getCisFamilyTitle('cis_rhel9_linux', '5')).toBe(
      'Access, Authentication and Authorization',
    );
    expect(getCisFamilyTitle('cis_win2022', '18')).toBe(
      'Administrative Templates (Computer)',
    );
    expect(getCisFamilyTitle('cis_ubuntu24-04', '4')).toBe(
      'Host Based Firewall',
    );
  });

  it('follows the layout of each benchmark', () => {
    // Debian 10 v2.0.0 swaps families 4 and 5 compared with Debian 11 v1.0.0.
    expect(getCisFamilyTitle('cis_debian10', '4')).toBe(
      'Access, Authentication and Authorization',
    );
    expect(getCisFamilyTitle('cis_debian11', '4')).toBe('Logging and Auditing');
  });

  it('returns nothing for unknown policies, families or unsafe keys', () => {
    expect(getCisFamilyTitle('custom_policy', '1')).toBeUndefined();
    expect(getCisFamilyTitle('cis_rhel9_linux', '99')).toBeUndefined();
    expect(getCisFamilyTitle('cis_rhel9_linux', undefined)).toBeUndefined();
    expect(getCisFamilyTitle(undefined, '1')).toBeUndefined();
    expect(getCisFamilyTitle('__proto__', '1')).toBeUndefined();
    expect(getCisFamilyTitle('cis_rhel9_linux', 'constructor')).toBeUndefined();
  });

  it('keys families by number and keeps titles clean', () => {
    for (const families of Object.values(cisFamiliesFile)) {
      for (const [family, title] of Object.entries(families)) {
        expect(family).toMatch(/^[0-9]+$/);
        expect(title).toBe(title.trim());
        expect(title.length).toBeGreaterThan(0);
      }
    }
  });
});
