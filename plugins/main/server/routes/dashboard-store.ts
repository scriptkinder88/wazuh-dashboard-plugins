/*
 * Routes of the dashboard store (records the dashboard keeps in the indexer, see
 * common/dashboard-store.ts). Any authenticated user can read; writes need a dashboard
 * administrator. The indexer is accessed as the internal user, so the store does not depend on
 * each user's index permissions; who changed a record is taken from the session.
 */
import { IRouter } from 'opensearch_dashboards/server';
import { schema } from '@osd/config-schema';
import {
  DASHBOARD_STORE_ID_RE,
  DASHBOARD_STORE_KIND_RE,
  DashboardStoreCollection,
  isDashboardStoreCollection,
} from '../../common/dashboard-store';
import {
  StoreConflictError,
  deleteRecord,
  listRecords,
  putRecord,
} from '../lib/dashboard-store';
import { ErrorResponse } from '../lib/error-response';
import { routeDecoratorProtectedAdministrator } from '../controllers/decorators';

const collection = schema.string({
  validate: value =>
    isDashboardStoreCollection(value) ? undefined : 'unknown collection',
});
const id = schema.string({
  validate: value =>
    DASHBOARD_STORE_ID_RE.test(value) ? undefined : 'invalid record id',
});
const kind = schema.string({
  validate: value =>
    DASHBOARD_STORE_KIND_RE.test(value) ? undefined : 'invalid kind',
});

const fail = (error: unknown, code: number, response) => {
  if (error instanceof StoreConflictError) {
    return ErrorResponse(error.message, code, 409, response);
  }
  const message = error instanceof Error ? error.message : String(error);
  return ErrorResponse(message, code, 500, response);
};

const currentUser = async (context, request) => {
  try {
    const { username } = await context.wazuh.security.getCurrentUser(
      request,
      context,
    );
    return username || '';
  } catch {
    return '';
  }
};

export const DashboardStoreRoutes = (router: IRouter) => {
  // who is changing records, for the audit fields the dashboard writes elsewhere (agent.conf)
  router.get(
    { path: '/api/dashboard-store-user', validate: false },
    async (context, request, response) =>
      response.ok({ body: { username: await currentUser(context, request) } }),
  );

  router.get(
    {
      path: '/api/dashboard-store/{collection}',
      validate: {
        params: schema.object({ collection }),
        query: schema.object({
          kind: schema.maybe(kind),
          key: schema.maybe(schema.string({ maxLength: 512 })),
          size: schema.maybe(schema.number({ min: 1, max: 10000 })),
        }),
      },
    },
    async (context, request, response) => {
      try {
        const items = await listRecords(
          context.core.opensearch.client.asInternalUser,
          request.params.collection as DashboardStoreCollection,
          request.query,
        );
        return response.ok({ body: { items } });
      } catch (error) {
        return fail(error, 9201, response);
      }
    },
  );

  router.put(
    {
      path: '/api/dashboard-store/{collection}/{id}',
      validate: {
        params: schema.object({ collection, id }),
        body: schema.object({
          kind,
          key: schema.string({ minLength: 1, maxLength: 512 }),
          data: schema.recordOf(schema.string(), schema.any()),
          seqNo: schema.maybe(schema.number({ min: 0 })),
          primaryTerm: schema.maybe(schema.number({ min: 1 })),
          create: schema.boolean({ defaultValue: false }),
        }),
      },
    },
    routeDecoratorProtectedAdministrator(9202)(
      async (context, request, response) => {
        try {
          const result = await putRecord(
            context.core.opensearch.client.asInternalUser,
            request.params.collection as DashboardStoreCollection,
            { id: request.params.id, ...request.body },
            await currentUser(context, request),
          );
          return response.ok({ body: result });
        } catch (error) {
          return fail(error, 9202, response);
        }
      },
    ),
  );

  router.delete(
    {
      path: '/api/dashboard-store/{collection}/{id}',
      validate: {
        params: schema.object({ collection, id }),
        query: schema.object({
          seqNo: schema.maybe(schema.number({ min: 0 })),
          primaryTerm: schema.maybe(schema.number({ min: 1 })),
        }),
      },
    },
    routeDecoratorProtectedAdministrator(9203)(
      async (context, request, response) => {
        try {
          await deleteRecord(
            context.core.opensearch.client.asInternalUser,
            request.params.collection as DashboardStoreCollection,
            request.params.id,
            request.query,
          );
          return response.ok({ body: {} });
        } catch (error) {
          return fail(error, 9203, response);
        }
      },
    ),
  );
};
