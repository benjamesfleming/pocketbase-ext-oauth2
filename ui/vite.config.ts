import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile";
import path from "path";

export default defineConfig({
    plugins: [viteSingleFile()],
    build: {
        outDir: 'dist',
        rollupOptions: {
            input: {
                login: path.resolve(__dirname, 'src/login.html'),
            },
            external: [
                /^\/_\/fonts/,
            ]
        },
    },
});