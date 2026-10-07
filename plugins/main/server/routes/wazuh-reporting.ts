/*
 * Wazuh app - Module for Wazuh reporting routes
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
import { IRouter } from 'opensearch_dashboards/server';
import { schema } from '@osd/config-schema';
import { WazuhReportingCtrl } from '../controllers';
import { REPORTS_SCA_MAX_AGENTS } from '../../common/constants';

export function WazuhReportingRoutes(router: IRouter) {
  const ctrl = new WazuhReportingCtrl();

  // Builds the SCA PDF report of the selected agents and returns the file.
  router.post(
    {
      path: '/reports/sca',
      validate: {
        body: schema.object({
          agents: schema.arrayOf(schema.string({ minLength: 1 }), {
            minSize: 1,
            maxSize: REPORTS_SCA_MAX_AGENTS,
          }),
          details: schema.boolean({ defaultValue: false }),
        }),
      },
    },
    (context, request, response) =>
      ctrl.createScaReport(context, request, response),
  );
}
