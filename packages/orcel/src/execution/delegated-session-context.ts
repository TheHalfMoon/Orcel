/** Returns whether this session was created as a delegated child behind a parent input proxy. */
export function hasDelegatedSessionContext(
  serializedContext: Readonly<Record<string, unknown>>,
): boolean {
  if (serializedContext["orcel.sessionCallback"] !== undefined) return true;
  const channel = serializedContext["orcel.channel"];
  return (
    typeof channel === "object" && channel !== null && Reflect.get(channel, "kind") === "subagent"
  );
}
