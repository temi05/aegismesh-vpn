// Скрипт отправки сгенерированного дизайна Stitch и установочного файла AegisMesh-VPN.apk в Telegram
import fs from 'node:fs';
import path from 'node:path';

function loadLocalEnv(): Record<string, string> {
  const out: Record<string, string> = {};
  try {
    const envPath = path.resolve(process.cwd(), '.env');
    if (fs.existsSync(envPath)) {
      const raw = fs.readFileSync(envPath, 'utf-8');
      for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx > 0) {
          out[trimmed.slice(0, eqIdx).trim()] = trimmed.slice(eqIdx + 1).trim();
        }
      }
    }
  } catch {
    // Игнорируем ошибку чтения .env
  }
  return out;
}

const localEnv = loadLocalEnv();
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || localEnv.TELEGRAM_BOT_TOKEN || '';
const CHAT_ID = process.env.TELEGRAM_CHAT_ID || localEnv.TELEGRAM_CHAT_ID || '';

async function sendTelegramFile(
  endpoint: 'sendPhoto' | 'sendDocument',
  fieldName: 'photo' | 'document',
  filePath: string,
  fileName: string,
  caption: string
) {
  const buf = fs.readFileSync(filePath);
  const form = new FormData();
  form.append('chat_id', CHAT_ID);
  form.append('caption', caption);
  form.append('parse_mode', 'HTML');
  form.append(fieldName, new Blob([buf]), fileName);

  const res = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${endpoint}`, {
    method: 'POST',
    body: form,
  });
  const json = await res.json();
  console.log(`[Telegram ${endpoint}]`, JSON.stringify(json));
  return json;
}

async function main() {
  const mode = process.argv[2] || 'all';
  const screenshotPath = path.resolve(
    'C:/Users/Темирлан/.gemini/antigravity/brain/3aac66ac-7a4e-42ae-b477-06b9c472fb2c/stitch-desktop-design.png'
  );
  const apkDebugPath = path.resolve(
    process.cwd(),
    'android/app/build/outputs/apk/debug/app-debug.apk'
  );
  const apkFriendlyPath = path.resolve(process.cwd(), 'AegisMesh-VPN.apk');

  if (mode === 'photo' || mode === 'all') {
    if (fs.existsSync(screenshotPath)) {
      await sendTelegramFile(
        'sendPhoto',
        'photo',
        screenshotPath,
        'AegisMesh-Stitch-Design.png',
        '🛡️ <b>AegisMesh VPN — Тактический Щит и Каскад Автозамены (1 ➔ 2 ➔ 3)</b>\n\nМакет из <b>Stitch MCP (Tactical Telemetry)</b> успешно интегрирован в десктопное приложение Windows (Electron) и мобильную сборку Android!'
      );
    }
  }

  if (mode === 'apk' || mode === 'all') {
    if (fs.existsSync(apkDebugPath)) {
      fs.copyFileSync(apkDebugPath, apkFriendlyPath);
      await sendTelegramFile(
        'sendDocument',
        'document',
        apkFriendlyPath,
        'AegisMesh-VPN.apk',
        '🛡️ <b>AegisMesh-VPN.apk v3.5 — Жёсткий анти-РФ фильтр для ИИ-шлюза (Gemini / ChatGPT / Grok) и Адский стресс-стенд на 240 серверов</b>\n\n🚀 <b>Что исправлено в v3.5:</b>\n• <b>Полный запрет РФ/релеев для ИИ:</b> <code>proxy-ai</code> больше никогда не выбирает российские серверы, <code>[через РФ]</code>, <code>LTE #1</code> и <code>YouTube без рекламы</code> даже на холодном старте при пинге 15 мс.\n• <b>Защита от ложных AI OK:</b> 302-редиректы Gemini и обманчивые флаги 🇳🇱/🇫🇮 без подтверждённого <code>googleCountry</code> больше не получают ложный статус <code>AI OK</code>.\n• <b>Устранён DNS-слив пробника:</b> запросы проверки ИИ на <code>127.0.0.1:20809</code> идут строго через выделенный <code>dns-ai-probe</code>.\n• <b>Убрана ловушка urltest:</b> <code>auto-failover</code> удалён из <code>proxy-ai</code>, а старый кэш проверок автоматически сброшен.'
      );
    }
  }
}

void main();
