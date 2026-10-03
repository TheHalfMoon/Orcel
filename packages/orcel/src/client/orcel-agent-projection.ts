import type { OrcelAgentReducer, OrcelAgentReducerEvent } from "#client/reducer.js";

/** Owns reducer replay when optimistic events are replaced by server events. */
export class OrcelAgentProjection<TData> {
  readonly #reducer: OrcelAgentReducer<TData>;
  #events: readonly OrcelAgentReducerEvent[];
  #data: TData;

  constructor(reducer: OrcelAgentReducer<TData>, events: readonly OrcelAgentReducerEvent[]) {
    this.#reducer = reducer;
    this.#events = events;
    this.#data = this.#reduce();
  }

  get data(): TData {
    return this.#data;
  }

  reset(): void {
    this.#events = [];
    this.#data = this.#reducer.initial();
  }

  append(event: OrcelAgentReducerEvent): void {
    this.#events = [...this.#events, event];
    this.#data = this.#reducer.reduce(this.#data, event);
  }

  remove(predicate: (event: OrcelAgentReducerEvent) => boolean): void {
    this.#events = this.#events.filter((event) => !predicate(event));
    this.#data = this.#reduce();
  }

  replace(
    predicate: (event: OrcelAgentReducerEvent) => boolean,
    replacement: OrcelAgentReducerEvent,
  ): void {
    const index = this.#events.findIndex(predicate);
    this.#events =
      index === -1
        ? [...this.#events, replacement]
        : this.#events.map((event, i) => (i === index ? replacement : event));
    this.#data = this.#reduce();
  }

  #reduce(): TData {
    let data = this.#reducer.initial();
    for (const event of this.#events) data = this.#reducer.reduce(data, event);
    return data;
  }
}
