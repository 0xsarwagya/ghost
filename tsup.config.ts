import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    server: "src/server.ts",
  },
  format: ["esm"],
  dts: false,
  sourcemap: true,
  clean: true,
  target: "es2022",
});
