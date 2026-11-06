import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";

// Tauri serves the built files; the dev server port is the one tauri.conf.json's devUrl names.
export default defineConfig({
  plugins: [solid()],
  server: { port: 5173, strictPort: true },
  build: { target: "safari16" },
  test: { environment: "node" },
});
