import { defineDynamic } from "@orcel/orcel/tools";

export default defineDynamic({
  events: {
    "session.started": async () => {
      return null;
    },
  },
});
