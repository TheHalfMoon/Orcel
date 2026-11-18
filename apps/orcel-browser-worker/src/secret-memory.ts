// SG-000135 OB-07b: a page's memory of its password fields.
//
// A sign-in form often has a "show password" toggle that turns the password
// input into a plain text input. Read on its own, the field then looks like
// any text field. The challenge detector (challenge.ts) records each
// password field it sees, by the engine's backend node id and by its name
// and id, so a field that was a password field stays one: the detector still
// holds the page as a sign-in page, and `isSecretField` (verify.ts) still
// refuses to read or fill it. Nothing here holds a field's value.

/// What one page remembers. Bounded; the oldest entries go first.
export interface SecretMemory {
  backends: Set<number>;
  /// `name:<name>` and `id:<id>`, lower-case.
  names: Set<string>;
}

/// The most backend ids and names one page remembers, each.
export const MAX_REMEMBERED = 256;
/// The longest name or id remembered.
const MAX_NAME_CHARS = 256;

const memories = new WeakMap<object, SecretMemory>();

/// The memory of `page` (any object that stands for one page), created on
/// first use and dropped with the page.
export function secretMemory(page: object): SecretMemory {
  let memory = memories.get(page);
  if (!memory) {
    memory = { backends: new Set(), names: new Set() };
    memories.set(page, memory);
  }
  return memory;
}

/// The memory of `page`, if it has one (never creates).
export function existingSecretMemory(page: object): SecretMemory | undefined {
  return memories.get(page);
}

function bounded<T>(set: Set<T>, value: T): void {
  set.delete(value);
  set.add(value);
  while (set.size > MAX_REMEMBERED) {
    const oldest = set.values().next();
    if (oldest.done === true) break;
    set.delete(oldest.value);
  }
}

function key(kind: "name" | "id", value: string | undefined): string | undefined {
  const text = (value ?? "").trim().toLowerCase();
  return text.length > 0 && text.length <= MAX_NAME_CHARS ? `${kind}:${text}` : undefined;
}

/// Record a password field.
export function rememberSecretField(memory: SecretMemory, backend: number | undefined, name: string | undefined, id: string | undefined): void {
  if (backend !== undefined) bounded(memory.backends, backend);
  for (const entry of [key("name", name), key("id", id)]) if (entry !== undefined) bounded(memory.names, entry);
}

/// Whether the element with this backend id was a password field.
export function wasSecretField(memory: SecretMemory, backend: number | undefined): boolean {
  return backend !== undefined && memory.backends.has(backend);
}

/// Whether a field with this name or id was a password field on the page.
export function wasSecretName(memory: SecretMemory, name: string, id: string): boolean {
  return [key("name", name), key("id", id)].some((entry) => entry !== undefined && memory.names.has(entry));
}
