# tg-claude-listener

Let a **Claude Code** session watch a Telegram chat and answer it from your own account.

New messages in the chats you pick wake the session up. Claude reads them, does the work and replies, signed «🤖 **Claude:**» so the other side knows an AI is writing. You can also hand Claude a task right from Telegram: type `/ai …` in that chat yourself.

How it works:
- `tools/watch_chat.py` is a small [Telethon](https://github.com/LonamiWebs/Telethon) listener. It prints one line to stdout per batch of new messages.
- Claude Code runs it under its **Monitor** tool, so every line becomes an event in the session. There is no polling and no bot: it is your own user account.
- `tools/send_reply.py` sends Claude's replies. The «Claude:» signature uses a Telegram Premium custom emoji; without Premium it shows as 🤖.

[Русская инструкция](README.ru.md)

## Setup (once, by you)
1. Python 3.11+, then `pip install -r requirements.txt`.
2. Create an API app at https://my.telegram.org (API development tools). Copy `.env.example` to `.env` and fill in `TELEGRAM_API_ID` and `TELEGRAM_API_HASH`.
3. Log in **yourself, in a terminal**: `python login.py`. It asks for your phone, the login code and your 2FA password, and writes `sessions/desktop.session`.
   > The session file is a full key to your Telegram account. Never share it, commit it, or let anyone else read it. `.gitignore` already excludes it.
4. Test it: `python tools/send_reply.py --chat me --text "test"` should land in Saved Messages.

If Telegram is reachable only through a proxy or VPN port, set `TELEGRAM_PROXY_CHAIN=socks5://127.0.0.1:<port>,direct` in `.env`. Without it, `netpath.py` tries the system proxy and the usual VPN ports, then a direct connection.

## Use it from Claude Code
Open Claude Code in this folder and say: *"start the Telegram listener on chat X following SKILL.md"*. [`SKILL.md`](SKILL.md) holds the instructions Claude follows. You can also copy it to `~/.claude/skills/telegram-listener/` so it works from any project; in that case set `TG_LISTENER_HOME` to this folder.

Under the hood Claude runs:
```bash
F=$(python tools/watch_chat.py --print-filter)
python -u tools/watch_chat.py --chat "<id | @username | part of the title>" \
  --state notes/watch_state.json --log notes/incoming.log 2>&1 | grep --line-buffered -E "$F"
```
and replies with
```bash
python tools/send_reply.py --chat <chat_id> --text-file reply.txt [--reply-to <msg_id>] [--file doc.pdf]
```

What the listener does:
- **Which messages it passes on.** Incoming messages only; messages from bots are skipped (`--include-bots` to keep them). Your own outgoing messages pass only when they start with `/ai`, and these are marked `"owner_call": true`.
- **Restarts lose nothing.** It catches up from `--state` on restart. It also re-checks the chat history every 30 s, because a dropped push update is otherwise silent.
- **Connection health is reported.** It prints when the connection drops and when it comes back, and writes an `ALIVE` heartbeat every 10 minutes to its log.
- **Several chats at once:** repeat `--chat`. Use `--quiet N` to batch a burst of messages into one wake-up.
- **Lifetime.** The Monitor lives only as long as the Claude session. Re-arm it every 30 minutes (Claude does this itself), and start it again in a new session.

## Safety
Claude acts as **you** in that chat. [`SKILL.md`](SKILL.md) tells it to answer questions but never to move money, deploy, or change anything on the strength of a chat message: it passes such requests to you instead. Read it and tighten it for your case.

## License
MIT
