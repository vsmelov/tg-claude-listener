# Telegram-слушатель для Claude Code

Claude в открытой сессии **сам просыпается**, когда в выбранном Telegram-чате появляются новые сообщения. Он читает их, делает работу и отвечает от твоего аккаунта с пометкой «🤖 Claude:», чтобы собеседник видел, что пишет ИИ.

Как устроено:
- `tools/watch_chat.py` — слушатель. Он держит соединение с Telegram и печатает в stdout строку на каждую пачку новых сообщений.
- Claude запускает его под своим тулом **Monitor**: каждая такая строка будит сессию.
- `tools/send_reply.py` — отправляет ответы с подписью Claude.

## Установка (один раз, делаешь сам)
1. Python 3.11+. В этой папке: `pip install -r requirements.txt`.
2. Получи API-ключ Telegram: https://my.telegram.org → API development tools → create app. Скопируй `.env.example` в `.env` и впиши `TELEGRAM_API_ID` и `TELEGRAM_API_HASH`.
3. **Сам в терминале** (не через Claude): `python login.py`. Он попросит телефон, код из Telegram и пароль 2FA, если он есть. Появится `sessions/desktop.session`.
   ⚠️ Этот файл — ключ к твоему Telegram. Никому не отправляй и не клади в git или облако.
4. Проверка: `python tools/send_reply.py --chat me --text "тест"` — сообщение должно прийти тебе в «Избранное».

Если Telegram у тебя работает только через VPN или прокси, впиши в `.env`:
`TELEGRAM_PROXY_CHAIN=socks5://127.0.0.1:<порт>,direct`.
Без этого скрипт сам пробует системный прокси и типичные порты VPN.

## Запуск в сессии Claude Code
Скажи своему Claude: «подключи слушатель Telegram на чат X по инструкции в SKILL.md из этой папки». Он сделает так:
```bash
F=$(python tools/watch_chat.py --print-filter)
python -u tools/watch_chat.py --chat "<id, @username или часть названия чата>" \
    --state notes/watch_state.json --log notes/incoming.log 2>&1 | grep --line-buffered -E "$F"
```
- Команда запускается под тулом **Monitor**, `timeout_ms` = 1800000. Каждые 30 минут Monitor перевзводится той же командой. Пропущенное за паузу слушатель догонит сам по `notes/watch_state.json`.
- Монитор будит только строками `BATCH …`. Сами тексты сообщений Claude читает из `notes/incoming.log`: последние строки, jsonl.
- Ответ отправляется так: `python tools/send_reply.py --chat <id> --text-file reply.txt [--reply-to <msg_id>]`.
- **`/ai` в чате.** Если ты сам напишешь в этом чате сообщение, начинающееся с `/ai …`, слушатель отдаст его Claude как задание от тебя.
- Слушатель живёт, пока открыта сессия. В новой сессии его подключают заново.

## Полезное
- Несколько чатов сразу: `--chat A --chat B`.
- Копить сообщения и отдавать пачкой: `--quiet 60` — пачка уходит после 60 с тишины. По умолчанию каждое сообщение отдаётся сразу.
- Премиум-эмодзи Claude в подписи видно, только если у аккаунта есть Telegram Premium. Иначе будет обычный 🤖.
