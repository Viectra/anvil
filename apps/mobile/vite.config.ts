import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [tailwindcss(), svelte()],
  clearScreen: false,
  server: {
    host: "0.0.0.0",
    port: 1421,
    strictPort: true,
  },
  build: {
    target: ["es2022", "safari16", "chrome105"],
    outDir: "dist",
    emptyOutDir: true,
  },
});
