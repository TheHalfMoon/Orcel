/**
 * Local access point for the `kaf dev` terminal-UI test harness used by the
 * `tui-*.ts` smoke tests. The harness is test infrastructure, not part of
 * kaf's public API, so it is intentionally absent from the package's
 * `exports` map; TUI smoke tests reach the built file directly by path instead.
 *
 * Requires `pnpm run build:js` to have produced `packages/kaf/dist` first.
 */
export {
  AUTHORED_ARTIFACTS_UPDATED_LOG_LINE,
  KafTUIRunner,
  createPromptCommandHandler,
  promptCommandsFor,
  type KafTUIRunnerOptions,
  formatChangeDetectedLogLine,
  MockScreen,
  MockUserInput,
  TerminalRenderer,
} from "../../../dist/src/cli/dev/tui/test/index.js";
