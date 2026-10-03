import { defineDynamic } from "orcel";

export default defineDynamic({
  events: {
    "session.started": () => null,
  },
});
