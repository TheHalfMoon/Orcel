import tailwindcss from "@tailwindcss/vite";

export default defineNuxtConfig({
  modules: ["kaf/nuxt"],

  css: ["~/assets/css/main.css"],

  devtools: { enabled: true },

  compatibilityDate: "2026-05-27",

  vite: {
    plugins: [tailwindcss()],
  },
});
