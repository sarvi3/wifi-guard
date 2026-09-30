import { defineConfig } from "@lovable.dev/vite-tanstack-config";

export default defineConfig({
  tanstackStart: {
    server: { entry: "server" },
  },

  nitro: {
    preset: "node-server",
  },

  vite: {
    server: {
      port: 8080,
      strictPort: true,
    },
  },
});