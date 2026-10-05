import { defineDynamic } from "@orcel/orcel";

export default defineDynamic({
  events: {
    "session.started": () => null,
  },
});
