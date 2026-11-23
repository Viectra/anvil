import { copyFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig, type Plugin } from "vite";

function mv3ManifestPlugin(target: "chromium" | "firefox"): Plugin {
  return {
    name: "anvil-mv3-manifest",
    closeBundle() {
      const outDir = resolve(__dirname, `dist/${target}`);
      mkdirSync(resolve(outDir, "icons"), { recursive: true });
      const srcManifest = resolve(__dirname, `manifests/${target}.manifest.json`);
      copyFileSync(srcManifest, resolve(outDir, "manifest.json"));
      const iconPath = resolve(__dirname, "icons/anvil-icon.svg");
      if (existsSync(iconPath)) {
        copyFileSync(iconPath, resolve(outDir, "icons/anvil-icon.svg"));
      }
      const pkgDir = resolve(__dirname, "src/wasm-pkg");
      if (!existsSync(pkgDir)) {
        writeFileSync(
          resolve(outDir, ".wasm-build-note.txt"),
          "Run wasm-pack build ../../crates/anvil-wasm --target web --out-dir ../../apps/extension/src/wasm-pkg before loading.",
        );
      }
    },
  };
}

export default defineConfig(({ mode }) => {
  const target: "chromium" | "firefox" = mode === "firefox" ? "firefox" : "chromium";
  return {
    plugins: [tailwindcss(), svelte(), mv3ManifestPlugin(target)],
    build: {
      outDir: `dist/${target}`,
      emptyOutDir: true,
      target: "es2022",
      rollupOptions: {
        input: {
          popup: resolve(__dirname, "src/popup/index.html"),
          background: resolve(__dirname, "src/background/index.ts"),
          content: resolve(__dirname, "src/content/index.ts"),
        },
        output: {
          entryFileNames: (chunk) => {
            if (chunk.name === "background") return "background.js";
            if (chunk.name === "content") return "content.js";
            return "assets/[name]-[hash].js";
          },
          chunkFileNames: "assets/[name]-[hash].js",
          assetFileNames: "assets/[name]-[hash][extname]",
        },
      },
    },
  };
});
