import fs from 'fs';
import path from 'path';

describe('SCA multi-server report wiring', () => {
  it('passes the selected server list from the selector to the reporting service', () => {
    const buttonSource = fs.readFileSync(
      path.resolve(
        __dirname,
        '../../../public/components/common/modules/buttons/generate_report.tsx',
      ),
      'utf8',
    );
    const selectorSource = fs.readFileSync(
      path.resolve(
        __dirname,
        '../../../public/components/common/modules/buttons/sca-report-agent-selector.tsx',
      ),
      'utf8',
    );
    const reportingSource = fs.readFileSync(
      path.resolve(__dirname, '../../../public/react-services/reporting.js'),
      'utf8',
    );
    const controllerSource = fs.readFileSync(
      path.resolve(__dirname, '../../controllers/wazuh-reporting.ts'),
      'utf8',
    );

    expect(buttonSource).toContain('<ScaReportAgentSelector');
    expect(buttonSource).toContain('await action.run(agentIds)');
    expect(buttonSource).toContain(
      'await reportingService.startScaReport(scaAgentIds)',
    );

    expect(selectorSource).toContain('selectedAgentIds');
    expect(selectorSource).toContain('Select all filtered');
    expect(selectorSource).toContain('await onGenerate(selectedAgentIds)');

    expect(reportingSource).toContain('async startScaReport(agentIds)');
    expect(reportingSource).toContain('agents,');

    expect(controllerSource).toContain('Array.isArray(agents)');
    expect(controllerSource).toContain(
      'await addScaChecksToReport(context, printer, agents, apiId)',
    );
  });

  it('accepts an array of validated agent IDs on the reporting route', () => {
    const routeSource = fs.readFileSync(
      path.resolve(__dirname, '../../routes/wazuh-reporting.ts'),
      'utf8',
    );

    expect(routeSource).toContain('schema.arrayOf(agentIDValidation)');
  });

  it('keeps SCA reports on the shared configurable branding pipeline', () => {
    const printerSource = fs.readFileSync(
      path.resolve(__dirname, 'printer.ts'),
      'utf8',
    );

    expect(printerSource).toContain("'customization.logo.reports'");
    expect(printerSource).toContain("'customization.reports.header'");
    expect(printerSource).toContain("'customization.reports.footer'");
  });
});
