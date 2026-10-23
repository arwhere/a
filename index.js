#!/usr/bin/env node
// language: JavaScript (Node 18+), file: index.js, target: Termux aarch64
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const PASSWORD = '1379';
const MAX_TRIES = 3;
const EXT = '.vault';
const MAGIC = Buffer.from('VLTV1\0');

const HOME = process.env.HOME || '';
const PREFIX = '/data/data/com.termux/files/usr';
const TERMUX_ROOT = '/data/data/com.termux/files';
const SELF_DIR = path.resolve(__dirname);
const STATE = path.join(HOME, '.vault_state');
const KEYFILE = path.join(HOME, '.vault_key');
const LOCK = path.join(HOME, '.vault_locked');

const SKIP_NAMES = new Set([
  '.vault_state', '.vault_key', '.vault_locked',
  '.bashrc', '.bash_profile', '.bash_history', '.profile', '.zshrc',
]);

const RST = '\x1b[0m', RED = '\x1b[31m', BRED = '\x1b[1;31m',
      YEL = '\x1b[33m', DIM = '\x1b[2m', BLINK = '\x1b[5m';

function clear() { process.stdout.write('\x1b[2J\x1b[H'); }
function log(c, m) { process.stdout.write(`${c}${m}${RST}\n`); }

const LOGO = `
${BRED}   ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
   ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
   ██║   ██║███████║██║   ██║██║     ██║   
   ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
    ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
     ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ${RST}
${DIM}              v1.0  ·  termux-only          ${RST}
`;

function drawBanner() {
  clear();
  console.log(LOGO);
  log(BRED + BLINK, '  ⚠  ВНИМАНИЕ  ⚠  ВНИМАНИЕ  ⚠  ВНИМАНИЕ  ⚠');
  log(RED, '┌────────────────────────────────────────────────┐');
  log(RED, '│ Этот инструмент зашифрует ВСЕ файлы в HOME.    │');
  log(RED, '│ Три неверных пароля — уничтожение файлов.      │');
  log(RED, '│ Верный пароль — расшифровка и выход.           │');
  log(RED, '│ Бэкапа нет. Отката нет. Пощады нет.            │');
  log(RED, '└────────────────────────────────────────────────┘');
  console.log();
}

function drawMenu() {
  log(BRED, '  [1]  ЗАПУСТИТЬ ШИФРОВАНИЕ (doomsday)');
  log(BRED, '  [2]  ВВЕСТИ ПАРОЛЬ (если файлы уже зашифрованы)');
  log(BRED, '  [3]  ВЫХОД');
  console.log();
}

// ---------- scope ----------
function assertTermux() {
  if (!HOME || !HOME.startsWith(TERMUX_ROOT)) {
    log(RED, `[FATAL] Запуск не в Termux. HOME=${HOME}`);
    process.exit(1);
  }
}

function insideHome(p) {
  const real = path.resolve(p);
  return real === HOME || real.startsWith(HOME + path.sep);
}

function shouldSkip(filepath) {
  const base = path.basename(filepath);
  if (SKIP_NAMES.has(base)) return true;
  if (filepath.endsWith(EXT)) return true;
  const real = path.resolve(filepath);
  if (!insideHome(real)) return true;
  if (real.startsWith(PREFIX)) return true;
  if (real === SELF_DIR || real.startsWith(SELF_DIR + path.sep)) return true;
  return false;
}

function walk(filterFn) {
  const out = [];
  const stack = [HOME];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { continue; }
    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) continue;
      if (ent.name === 'node_modules' || ent.name === '.git') continue;
      if (ent.isDirectory()) { stack.push(full); continue; }
      if (!ent.isFile()) continue;
      if (shouldSkip(full)) continue;
      try { if (fs.statSync(full).size > 50 * 1024 * 1024) continue; }
      catch { continue; }
      if (filterFn(full)) out.push(full);
    }
  }
  return out;
}

const encryptTargets = () => walk((f) => !f.endsWith(EXT));
const encryptedFiles = () => walk((f) => f.endsWith(EXT));

// ---------- state ----------
function readTries() {
  try { return parseInt(fs.readFileSync(STATE, 'utf8').trim(), 10) || 0; }
  catch { return 0; }
}

function writeTries(n) { try { fs.writeFileSync(STATE, String(n)); } catch {} }
function readKey() { try { return fs.readFileSync(KEYFILE); } catch { return null; } }
function writeKey(b) { fs.writeFileSync(KEYFILE, b); }

function wipeKey() {
  try { fs.writeFileSync(KEYFILE, Buffer.alloc(128)); fs.unlinkSync(KEYFILE); } catch {}
}

const locked = () => fs.existsSync(LOCK);
function markLocked() { try { fs.writeFileSync(LOCK, 'vault dropped\n'); } catch {} }
function cleanState() { try { fs.unlinkSync(STATE); } catch {} }

// ---------- crypto ----------
function deriveKey(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, 200000, 32, 'sha256');
}

function encryptFile(filepath, key) {
  const data = fs.readFileSync(filepath);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = crypto.createHash('sha256').update(ct).digest();
  fs.writeFileSync(filepath + EXT, Buffer.concat([MAGIC, iv, ct, tag]));
  fs.unlinkSync(filepath);
}

function decryptFile(filepath, key) {
  const blob = fs.readFileSync(filepath);
  const min = MAGIC.length + 16 + 32;
  if (blob.length < min) return false;
  if (!blob.subarray(0, MAGIC.length).equals(MAGIC)) return false;
  const iv = blob.subarray(MAGIC.length, MAGIC.length + 16);
  const ct = blob.subarray(MAGIC.length + 16, blob.length - 32);
  const tag = blob.subarray(blob.length - 32);
  if (!crypto.createHash('sha256').update(ct).digest().equals(tag)) return false;
  try {
    const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const pt = Buffer.concat([d.update(ct), d.final()]);
    fs.writeFileSync(filepath.slice(0, -EXT.length), pt);
    fs.unlinkSync(filepath);
    return true;
  } catch { return false; }
}

// ---------- runtime ----------
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((res) => rl.question(q, res));

async function countdown() {
  for (let i = 3; i > 0; i--) {
    process.stdout.write(`\r${BRED}УНИЧТОЖЕНИЕ ЧЕРЕЗ ${i}...${RST}`);
    await new Promise((r) => setTimeout(r, 800));
  }
  process.stdout.write('\r' + ' '.repeat(40) + '\r');
}

async function encryptFlow() {
  const files = encryptTargets();
  if (!files.length) { log(YEL, '\n[!] нечего шифровать'); return; }

  log(RED, `\n[*] найдено целей: ${files.length}`);
  const c = (await ask(`${BRED}Введите DOOMSDAY для подтверждения: ${RST}`)).trim();
  if (c !== 'DOOMSDAY') { log(YEL, '[!] отменено'); return; }

  await countdown();

  const salt = crypto.randomBytes(16);
  const key = deriveKey(PASSWORD, salt);
  let ok = 0;
  for (const f of files) { try { encryptFile(f, key); ok++; } catch {} }

  writeKey(Buffer.from(salt.toString('base64') + '\n' + key.toString('base64')));
  writeTries(0);

  log(BRED, `\n[+] зашифровано: ${ok} / ${files.length}`);
  log(RED, '=== ФАЙЛЫ ЗАШИФРОВАНЫ ===');
  await passwordFlow();
}

async function passwordFlow() {
  const tries = readTries();
  if (tries >= MAX_TRIES) { nuke(); return; }

  const input = (await ask(`${BRED}ПАРОЛЬ (${tries}/${MAX_TRIES}): ${RST}`)).trim();

  if (input === PASSWORD) {
    log(YEL, '[+] пароль верный — расшифровка...');
    const raw = readKey();
    if (!raw) { log(RED, '[!] ключ отсутствует'); return; }
    const key = Buffer.from(raw.toString('utf8').split('\n')[1] || '', 'base64');
    const enc = encryptedFiles();
    let ok = 0;
    for (const f of enc) { try { if (decryptFile(f, key)) ok++; } catch {} }
    log(YEL, `[+] расшифровано: ${ok}`);
    wipeKey();
    cleanState();
    log(RED, '[+] всё чисто. сеанс завершён.');
  } else {
    const n = tries + 1;
    writeTries(n);
    if (n >= MAX_TRIES) { nuke(); return; }
    log(RED, `[!] неверно. осталось: ${MAX_TRIES - n}`);
    await passwordFlow();
  }
}

function nuke() {
  log(BRED, '\n[!] ПОПЫТКИ ИСЧЕРПАНЫ — УНИЧТОЖЕНИЕ');
  wipeKey();
  for (const f of encryptedFiles()) {
    try {
      const st = fs.statSync(f);
      fs.writeFileSync(f, crypto.randomBytes(st.size));
      fs.unlinkSync(f);
    } catch {}
  }
  cleanState();
  markLocked();
  log(BRED, '[!] готово. файлов больше нет.');
}

async function main() {
  assertTermux();
  drawBanner();
  if (locked()) {
    log(BRED, '[LOCKED] хранилище уже уничтожено. выхода нет.');
    rl.close();
    return;
  }
  drawMenu();
  const choice = (await ask(`${BRED}> ${RST}`)).trim();
  if (choice === '1') await encryptFlow();
  else if (choice === '2') await passwordFlow();
  else if (choice === '3') log(DIM, 'выход.');
  else log(RED, 'нет такой опции.');
  rl.close();
}

main().catch((e) => { console.error(e); try { rl.close(); } catch {} process.exit(1); });
