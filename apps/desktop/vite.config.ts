import { env } from "node:process";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

const bridgeUrl = env.ANVIL_DESKTOP_BRIDGE_URL ?? "http://127.0.0.1:1425";
const bridgeToken = env.ANVIL_DESKTOP_BRIDGE_TOKEN ?? "";

export default defineConfig({
  plugins: [tailwindcss(), svelte()],
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
    proxy: {
      "/api/desktop-ipc": {
        target: bridgeUrl,
        changeOrigin: false,
        headers: bridgeToken ? { "x-anvil-bridge-token": bridgeToken } : undefined,
      },
    },
  },
  build: {
    target: ["es2022", "chrome105", "safari15"],
    outDir: "dist",
    emptyOutDir: true,
  },
});
