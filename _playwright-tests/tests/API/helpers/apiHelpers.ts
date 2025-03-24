/* eslint-disable @typescript-eslint/no-explicit-any */
import test from '@playwright/test';
import {
  Configuration,
  RepositoriesApi,
  ListRepositoriesRequest,
  BulkDeleteRepositoriesRequest,
  TemplatesApi,
  ListTemplatesRequest,
  DeleteTemplateRequest,
  ApiTaskInfoCollectionResponse,
  TasksApi,
  ListTasksRequest,
} from '../client';

// while condition is true, calls fn, waits interval (ms) between calls.
// condition's parameter should be the result of the function call.
export const poll = async (
  fn: () => Promise<any>,
  condition: (result: any) => boolean,
  interval: number,
) => {
  let result = await fn();
  while (condition(result)) {
    result = await fn();
    await timer(interval);
  }
  return result;
};

// timer in ms, must await e.g. await timer(num)
export const timer = (ms: number) => new Promise((res) => setTimeout(res, ms));

export const SmallRedHatRepoURL =
  'https://cdn.redhat.com/content/dist/rhel9/9/aarch64/codeready-builder/os/';

export const cleanupRepositories = async (client: Configuration, ...namesOrUrls: string[]) => {
  await test.step(
    `Cleaning up repositories, search terms: ${namesOrUrls.join(', ')}`,
    async () => {
      let uuidList: string[] = [];
      let snapshotReposList: string[] = [];
      for (const s of namesOrUrls) {
        const res = await new RepositoriesApi(client).listRepositories(<ListRepositoriesRequest>{
          origin: 'external,upload',
          search: s,
        });
        if (res.data?.length) {
          uuidList = uuidList.concat(res.data.map((v) => v.uuid!));
          snapshotReposList = snapshotReposList.concat(
            res.data.filter((r) => r.snapshot).map((r) => r.uuid!),
          );
        }
      }

      if (uuidList.length) {
        await new RepositoriesApi(client).bulkDeleteRepositoriesRaw(<BulkDeleteRepositoriesRequest>{
          apiUUIDListRequest: { uuids: [...new Set(uuidList)] },
        });
      } else {
        return;
      }

      if (snapshotReposList.length) {
        await timer(1000);

        const waitForTasks = (resp: ApiTaskInfoCollectionResponse) =>
          resp.data?.filter((t) => t.status == 'completed').length !== snapshotReposList.length;
        const getTask = () =>
          new TasksApi(client).listTasks(<ListTasksRequest>{
            type: 'delete-repository-snapshots',
            limit: snapshotReposList.length,
          });
        await poll(getTask, waitForTasks, 100);
      }
    },
    {
      box: true,
    },
  );
};

export const cleanupTemplates = async (client: Configuration, ...templateNames: string[]) => {
  await test.step(
    `Cleaning up templates, names: ${templateNames.join(', ')}`,
    async () => {
      let uuidList: string[] = [];
      for (const n of templateNames) {
        const res = await new TemplatesApi(client).listTemplates(<ListTemplatesRequest>{
          name: n,
        });
        if (res.data?.length) {
          uuidList = uuidList.concat(res.data.map((v) => v.uuid!));
        }
      }

      for (const u in uuidList) {
        await new TemplatesApi(client).deleteTemplateRaw(<DeleteTemplateRequest>{
          uuid: u,
        });
      }

      if (uuidList.length > 0) {
        await timer(1000);
        const waitForTasks = (resp: ApiTaskInfoCollectionResponse) =>
          resp.data?.filter((t) => t.status == 'completed').length !== uuidList.length;
        const getTask = () =>
          new TasksApi(client).listTasks(<ListTasksRequest>{
            type: 'delete-templates',
            limit: uuidList.length,
          });

        await poll(getTask, waitForTasks, 100);
      }
    },
    {
      box: true,
    },
  );
};
