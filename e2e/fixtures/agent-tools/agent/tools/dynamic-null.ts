import { defineDynamic } from "kaf/tools";

export default defineDynamic({
  events: {
    "session.started": async () => {
      return null;
    },
  },
});
