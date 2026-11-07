/**
 * i18n（P2.2 追加 · 网页端限定，外教课交付）：
 * - UI 全部走 t() 键值；协议运行日志保持英文（grep/演示可查，翻译不含协议事件文案）；
 * - 语言选择持久化 localStorage('pqe2e.lang')，缺省中文，可切英文；
 * - 目录/词表就地维护：新键加进 zh/en 两块即可，i18next 自动驱动重渲。
 */
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

const zh = {
  brand: 'pqe2e-chat',
  nav: { disconnected: '未连接', connected: '已连接 · {{name}}' },
  boot: {
    title: '开始会话',
    subtitle: '钱包即身份 · ML-KEM-768 + X25519 混合协商 · Double Ratchet · Merkle 目录校验',
    srv: '服务器地址',
    username: '用户名（如 alice）',
    pass: '设备口令（min 8）',
    connect: '连接',
    needName: '需要用户名',
    badPass: '口令过短（至少 8 位）',
  },
  side: {
    contacts: '联系人',
    me: 'me',
    groups: '群组',
    emptyGroups: '（尚无群 — 创建一个）',
    gid: '群 id',
    gname: '群名',
    members: '成员（逗号分隔）',
    create: '创建群（成员须在线 · 6s roll 窗口）',
  },
  chat: {
    noTarget: '（未选择会话）',
    placeholder: '输入消息 · Enter 发送',
    send: '发送',
    empty: '— 暂无消息（选择左侧联系人或群）—',
    e2eNote: '端到端密文经不可信中继',
  },
  groupCreate: {
    needGidName: '创建群：需要 群id 与 群名',
    missing: 'create：成员须在线；缺失: {{list}}',
    dup: 'create：群 id 已存在',
    rolled: '[#g] roll 已派发（ep={{ep}}）；收集签名声明（≤6s）',
  },
  foot: '课程作业演示 · TS 线 · 密码面：FIPS 203/204（noble）· 无服务器信任假设',
};

const en: typeof zh = {
  brand: 'pqe2e-chat',
  nav: { disconnected: 'Disconnected', connected: 'Connected · {{name}}' },
  boot: {
    title: 'Start a session',
    subtitle: 'Wallet-as-identity · ML-KEM-768 + X25519 hybrid agreement · Double Ratchet · Merkle-checked directory',
    srv: 'Server URL',
    username: 'Username (e.g. alice)',
    pass: 'Device passphrase (min 8)',
    connect: 'Connect',
    needName: 'Username required',
    badPass: 'Passphrase too short (min 8)',
  },
  side: {
    contacts: 'Contacts',
    me: 'me',
    groups: 'Groups',
    emptyGroups: '(no groups yet — create one)',
    gid: 'Group id',
    gname: 'Group name',
    members: 'Members (comma-separated)',
    create: 'Create group (members online · 6s roll window)',
  },
  chat: {
    noTarget: '(no conversation selected)',
    placeholder: 'Type a message · Enter to send',
    send: 'Send',
    empty: '— no messages yet (pick a contact or group on the left) —',
    e2eNote: 'end-to-end ciphertext via untrusted relay',
  },
  groupCreate: {
    needGidName: 'Create group: group id and name required',
    missing: 'create: members must be online; missing: {{list}}',
    dup: 'create: group id already exists',
    rolled: '[#g] roll dispatched (ep={{ep}}); collecting signed claims (≤6s)',
  },
  foot: 'Course demo · TS line · Crypto: FIPS 203/204 (noble) · No server trust assumed',
};

const saved = (localStorage.getItem('pqe2e.lang') as 'zh' | 'en' | null) ?? 'zh';

i18n.use(initReactI18next).init({
  resources: { zh: { translation: zh }, en: { translation: en } },
  lng: saved,
  fallbackLng: 'zh',
  interpolation: { escapeValue: false }, // React 自身转义
});

export function setLang(lng: 'zh' | 'en'): void {
  localStorage.setItem('pqe2e.lang', lng);
  document.documentElement.lang = lng;
  void i18n.changeLanguage(lng);
}
