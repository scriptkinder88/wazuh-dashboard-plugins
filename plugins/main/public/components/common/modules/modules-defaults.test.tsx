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

  it('adds the FIM rules management tab to Integrity monitoring', () => {
    const source = fs.readFileSync(
      path.resolve(__dirname, 'modules-defaults.tsx'),
      'utf8',
    );
    const fimBlock = source.match(/\n {2}fim:\s*\{[\s\S]*?\n {2}\},/)?.[0];

    expect(fimBlock).toContain("id: 'manage'");
    expect(fimBlock).toContain('component: FimManagement');
  });
});
