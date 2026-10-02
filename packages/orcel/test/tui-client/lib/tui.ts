/**
 * Local access point for the `orcel dev` terminal-UI test harness used by the
 * `tui-*.ts` smoke tests. The harness is test infrastructure, not part of
 * orcel's public API, so it is intentionally absent from the package's
 * `exports` map; TUI smoke tests reach the built file directly by path instead.
 *
 * Requires `pnpm run build:js` to have produced `packages/orcel/dist` first.
 */
export {
  AUTHORED_ARTIFACTS_UPDATED_LOG_LINE,
  OrcelTUIRunner,
  createPromptCommandHandler,
  promptCommandsFor,
  type OrcelTUIRunnerOptions,
  formatChangeDetectedLogLine,
  MockScreen,
  MockUserInput,
  TerminalRenderer,
} from "../../../dist/src/cli/dev/tui/test/index.js";
