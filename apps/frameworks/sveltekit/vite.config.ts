import adapter from "@sveltejs/adapter-vercel";
import { sveltekit } from "@sveltejs/kit/vite";
import tailwindcss from "@tailwindcss/vite";
import { kafSvelteKit } from "kaf/sveltekit";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [kafSvelteKit(), tailwindcss(), sveltekit({ adapter: adapter() })],
});
