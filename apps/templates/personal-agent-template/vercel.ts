import { withEve } from "kaf/vercel";

export default await withEve({
  services: {
    web: { framework: "nuxt", root: "apps/web" },
  },
  routes: [{ src: "^(.*)$", destination: { type: "service", service: "web" } }],
});
