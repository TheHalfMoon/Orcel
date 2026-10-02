/**
 * Supported runtime contract for one module-authored orcel definition.
 *
 * Module-backed authored sources may export the public definition directly or
 * export a zero-argument factory that returns the definition synchronously or
 * asynchronously when orcel loads the module in Node.js at runtime.
 */
export type ModuleDefinitionExport<TDefinition> =
  | TDefinition
  | (() => TDefinition | Promise<TDefinition>);
