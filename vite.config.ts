import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// web/ 前端构建：React + Tailwind v4 插件 + node 原生模块内存垫片（纯协议模块浏览器化）
// 注：vitest 与 vite 共用本配置 —— vite.root 指向 web/，vitest.root 保留仓库根（test/ 在此）；
// 别名（node:fs→内存垫片）只在 WEB_BUILD=1（pnpm web:build）时生效，避免污染 Node 侧测试。
const here = path.dirname(fileURLToPath(import.meta.url));
const isWebBuild = process.env.WEB_BUILD === '1';
export default defineConfig({
  root: 'web',
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: isWebBuild
      ? [
          { find: /^node:fs$/, replacement: path.resolve(here, 'web/fsshim.ts') },
          { find: /^node:path$/, replacement: path.resolve(here, 'web/fsshim.ts') },
          { find: /^node:crypto$/, replacement: path.resolve(here, 'web/fsshim.ts') },
        ]
      : [],
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: true,
  },
  test: {
    root: here,
  },
});
