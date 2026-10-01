/*
 * Wazuh app - Class for Wazuh reporting controller
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
import {
  OpenSearchDashboardsRequest,
  OpenSearchDashboardsResponseFactory,
  RequestHandlerContext,
} from 'src/core/server';
import { HTTP_STATUS_CODES, WAZUH_SCA_PATTERN } from '../../common/constants';
import { ErrorResponse } from '../lib/error-response';
import { ReportPrinter } from '../lib/reporting/printer';
import { addScaChecksToReport } from '../lib/reporting/sca-report';
import { normalizeAgentIds } from '../lib/reporting/sca-states-request';

const SCA_REPORT_ERROR_CODE = 5029;
// Indexer errors that are returned with their own status code.
const FORWARDED_ERROR_STATUS_CODES = [
  HTTP_STATUS_CODES.BAD_REQUEST,
  HTTP_STATUS_CODES.UNAUTHORIZED,
  HTTP_STATUS_CODES.FORBIDDEN,
  HTTP_STATUS_CODES.NOT_FOUND,
];

export class WazuhReportingCtrl {
  /**
   * Builds the SCA PDF report of the selected agents from the SCA states index
   * and returns it as the response body.
   */
  async createScaReport(
    context: RequestHandlerContext,
    request: OpenSearchDashboardsRequest<
      unknown,
      unknown,
      { agents: string[]; details?: boolean }
    >,
    response: OpenSearchDashboardsResponseFactory,
  ) {
    try {
      const agents = normalizeAgentIds(request.body.agents);

      if (!agents.length) {
        return response.badRequest({
          body: { message: 'Select at least one server for the SCA report.' },
        });
      }

      const details = request.body.details === true;
      context.wazuh.logger.debug(
        `Creating the SCA report of ${agents.length} agents (details: ${details})`,
      );

      const printer = new ReportPrinter(context.wazuh.logger);
      const generatedAt = new Date();

      printer.addContentWithNewLine({
        text: 'Security configuration assessment report',
        style: 'h1',
      });
      printer.addContentWithNewLine({
        text:
          `Generated: ${generatedAt.toISOString()} | Selected servers: ` +
          `${agents.length} | Source: ${WAZUH_SCA_PATTERN}`,
        style: 'standard',
      });

      await addScaChecksToReport(context, printer, agents, { details });

      const pdf = await printer.printToBuffer();
      const filename = `wazuh-sca-${(generatedAt.getTime() / 1000) | 0}.pdf`;

      context.wazuh.logger.debug(`SCA report ${filename} created`);

      return response.ok({
        headers: {
          'content-type': 'application/pdf',
          'content-disposition': `attachment; filename="${filename}"`,
        },
        body: pdf,
      });
    } catch (error: any) {
      const errorMessage =
        error?.meta?.body?.error?.reason || error?.message || String(error);
      const indexerStatusCode = Number(error?.meta?.statusCode);
      const statusCode = FORWARDED_ERROR_STATUS_CODES.includes(
        indexerStatusCode,
      )
        ? indexerStatusCode
        : HTTP_STATUS_CODES.INTERNAL_SERVER_ERROR;

      context.wazuh.logger.error(
        `Error creating the SCA report: ${errorMessage}`,
      );

      return ErrorResponse(
        errorMessage,
        SCA_REPORT_ERROR_CODE,
        statusCode,
        response,
      );
    }
  }
}
