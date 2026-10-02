import { defineDynamic } from "orcel/tools";

export default defineDynamic({
  events: {
    "session.started": async () => {
      return null;
    },
  },
});
