/**
 * P2.2 浏览器端构建产物冒烟（React + Vite 版）：
 *  - dist/index.html 存在且含 #root 与资源引用
 *  - JS/CSS 资源就位（Vite 哈希文件名）
 *  - 零外部 URL 引用（交付纪律：离线可演示）
 */
import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const dist = path.join(__dirname, '..', 'web', 'dist');

describe('P2.2 web build artifacts', () => {
  it('dist/index.html exists with #root and asset refs', () => {
    const html = fs.readFileSync(path.join(dist, 'index.html'), 'utf8');
    expect(html).toContain('id="root"');
    expect(html).toMatch(/assets\/index-.+\.js/);
  });

  it('assets present (js + css inside hashed filenames)', () => {
    const assets = fs.readdirSync(path.join(dist, 'assets'));
    expect(assets.some((f) => f.endsWith('.js'))).toBe(true);
    expect(assets.some((f) => f.endsWith('.css'))).toBe(true);
  });

  it('zero external URLs (offline-demo discipline, NOTES #14)', () => {
    const html = fs.readFileSync(path.join(dist, 'index.html'), 'utf8');
    expect((html.match(/https?:\/\//g) ?? []).length).toBe(0);
    for (const f of fs.readdirSync(path.join(dist, 'assets'))) {
      if (f.endsWith('.css')) {
        const css = fs.readFileSync(path.join(dist, 'assets', f), 'utf8');
        expect((css.match(/url\(https?:/g) ?? []).length, `css ${f}`).toBe(0);
      }
    }
  });
});
