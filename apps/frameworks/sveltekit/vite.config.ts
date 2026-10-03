import adapter from "@sveltejs/adapter-vercel";
import { sveltekit } from "@sveltejs/kit/vite";
import tailwindcss from "@tailwindcss/vite";
import { orcelSvelteKit } from "orcel/sveltekit";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [orcelSvelteKit(), tailwindcss(), sveltekit({ adapter: adapter() })],
});
