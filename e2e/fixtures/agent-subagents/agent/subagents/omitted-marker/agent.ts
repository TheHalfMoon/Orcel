import { defineDynamic } from "kaf";

export default defineDynamic({
  events: {
    "session.started": () => null,
  },
});
