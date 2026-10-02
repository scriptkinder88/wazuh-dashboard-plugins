import fs from 'fs';
import path from 'path';

describe('ModulesDefaults SCA reporting', () => {
  it('exposes the Generate report action on the SCA dashboard tab', () => {
    const source = fs.readFileSync(
      path.resolve(__dirname, 'modules-defaults.tsx'),
      'utf8',
    );

    const scaBlock = source.match(
      /sca:\s*\{[\s\S]*?availableFor:\s*\['manager', 'agent'\],[\s\S]*?\n\s*\},/,
    )?.[0];

    expect(scaBlock).toBeDefined();
    expect(scaBlock).toContain(
      'buttons: [ButtonExploreAgent, ButtonModuleGenerateReport]',
    );
  });

  it('adds the CIS-CAT management tab to Configuration Assessment', () => {
    const source = fs.readFileSync(
      path.resolve(__dirname, 'modules-defaults.tsx'),
      'utf8',
    );
    const scaBlock = source.match(
      /sca:\s*\{[\s\S]*?availableFor:\s*\['manager', 'agent'\],[\s\S]*?\n\s*\},/,
    )?.[0];

    expect(scaBlock).toContain("id: 'ciscat'");
    expect(scaBlock).toContain('component: CiscatManagement');
  });
});
