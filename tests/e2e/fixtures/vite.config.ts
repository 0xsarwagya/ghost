import { defineConfig } from "vite";
import path from "node:path";

const root = path.resolve(__dirname);

export default defineConfig({
  root,
  server: { host: "127.0.0.1", strictPort: true },
  resolve: {
    alias: {
      "@0xsarwagya/ghost/server": path.resolve(root, "../../../src/server.ts"),
      "@0xsarwagya/ghost": path.resolve(root, "../../../src/index.ts"),
      "@vectors": path.resolve(root, "../../protocol-vectors.ts"),
    },
  },
  build: { target: "esnext" },
});
