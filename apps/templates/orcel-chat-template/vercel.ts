import { withEve } from "orcel/vercel";

export default await withEve({
  services: {
    web: { framework: "nextjs", root: "apps/web" },
  },
  routes: [{ src: "^(.*)$", destination: { type: "service", service: "web" } }],
});
