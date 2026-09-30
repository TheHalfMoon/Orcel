import { resolveInstalledPackageInfo } from "#internal/application/package.js";
import {
  createAgentSourceRegistry,
  defineProgrammaticAgentSource,
  loadProgrammaticModuleNamespace,
  memoizeModuleNamespaceFactories,
  type AgentSourceRegistry,
  type AgentModuleBacking,
  type ProgrammaticModuleNamespace,
} from "#compiler/source-graph.js";

const revision = `kaf@${resolveInstalledPackageInfo().version}:compiled-manifest-v52`;

const localDefaults = defineProgrammaticAgentSource({
  id: "kaf:defaults",
  revision,
  modules: [
    { logicalPath: "agent.ts", loadNamespace: () => import("#framework/sources/modules/agent.js") },
    {
      logicalPath: "sandbox.ts",
      semanticRevision: "kaf:default-sandbox:v1",
      loadNamespace: () => import("#framework/sources/modules/sandbox.js"),
    },
    {
      logicalPath: "tools/bash.ts",
      loadNamespace: () => import("#tools/provided/bash.js"),
    },
    {
      logicalPath: "tools/read_file.ts",
      loadNamespace: () => import("#tools/provided/read-file.js"),
    },
    {
      logicalPath: "tools/write_file.ts",
      loadNamespace: () => import("#tools/provided/write-file.js"),
    },
    {
      logicalPath: "tools/web_fetch.ts",
      loadNamespace: () => import("#tools/provided/web-fetch.js"),
    },
    {
      logicalPath: "tools/load_skill.ts",
      loadNamespace: () => import("#tools/provided/load-skill.js"),
    },
    {
      logicalPath: "tools/connection_search.ts",
      loadNamespace: () => import("#tools/framework/connection-search.js"),
    },
    {
      logicalPath: "tools/web_search.ts",
      loadNamespace: () => import("#tools/provided/web-search.js"),
    },
  ],
});

const rootDefaults = defineProgrammaticAgentSource({
  id: "kaf:root-defaults",
  revision,
  modules: [
    {
      logicalPath: "tools/agent.ts",
      loadNamespace: () => import("#tools/framework/agent.js"),
    },
    {
      logicalPath: "channels/kaf.ts",
      loadNamespace: () => import("#framework/sources/modules/kaf-channel.js"),
    },
    {
      logicalPath: "channels/home.ts",
      loadNamespace: () => import("#framework/sources/modules/home-channel.js"),
    },
  ],
});

const memoryWrapperTemplateSource = defineProgrammaticAgentSource({
  id: "kaf:memory-wrapper",
  revision,
  modules: [
    {
      logicalPath: "tools/memory-wrapper.ts",
      loadNamespace: async (context) => {
        const { loadMemoryWrapperNamespace } =
          await import("#framework/sources/modules/memory-wrapper.js");
        return await loadMemoryWrapperNamespace(context);
      },
    },
  ],
});

export const frameworkAgentSourceRegistry: AgentSourceRegistry = createAgentSourceRegistry(
  [
    { applyTo: "all-local-nodes", source: localDefaults },
    { applyTo: "root", source: rootDefaults },
  ],
  { templates: [memoryWrapperTemplateSource] },
);

export const memoryWrapperTemplate = frameworkAgentSourceRegistry.templates.get(
  memoryWrapperTemplateSource.id,
)!;

export async function loadFrameworkProgrammaticModule(
  backing: Extract<AgentModuleBacking, { readonly kind: "programmatic" }>,
  dependencyNamespaces?: Readonly<Record<string, ProgrammaticModuleNamespace>>,
): Promise<ProgrammaticModuleNamespace> {
  return memoizeModuleNamespaceFactories(
    await loadProgrammaticModuleNamespace({
      backing,
      dependencyNamespaces,
      registries: [frameworkAgentSourceRegistry],
    }),
  );
}
