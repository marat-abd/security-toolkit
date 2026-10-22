
import os
import logging
from urllib.parse import urlparse
import re
import time

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def start(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    await update.message.reply_text(
        "Привет! Я бот для базовой проверки безопасности сайтов.\n\n"
        "Отправь домен, например: example.com"
    )



async def check_site(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    from security_toolkit.__main__ import run_assessment

    target = update.message.text.strip()

    if len(target) > 253:
        await update.message.reply_text(
            "Адрес слишком длинный. Отправь домен до 253 символов."
        )
        return

    url = target if "://" in target else f"https://{target}"
    parsed = urlparse(url)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or not re.fullmatch(r"[A-Za-z0-9.-]+", parsed.hostname)
        or "." not in parsed.hostname
    ):
        await update.message.reply_text(
            "Некорректный адрес. Пример: example.com"
        )
        return

    target = url

    now = time.monotonic()
    last_check = context.user_data.get("last_check", 0)

    if last_check and now - last_check < 30:
        await update.message.reply_text(
            "Подожди 30 секунд перед следующей проверкой."
        )
        return

    context.user_data["last_check"] = now

    if not target or " " in target:
        await update.message.reply_text(
            "Отправь один домен, например example.com"
        )
        return

    await update.message.reply_text(
        f"🔎 Проверяю безопасность {target}...\n"
        "Это может занять несколько секунд."
    )

    try:
        try:
            result = run_assessment(target)
        except Exception:
            logger.exception("Ошибка при проверке сайта")
            await update.message.reply_text(
                "Не удалось проверить сайт. Попробуй позже."
            )
            return


        score = result["score"]
        headers = result["headers"]
        tls = result["tls"]
        dns = result["dns"]

        message = (
            f"🛡 Отчёт безопасности\n\n"
            f"🌐 Сайт: {target}\n"
            f"📊 Оценка: {score['score']}/{score['max_score']} "
            f"({score['percentage']}%)\n"
            f"Уровень: {score['level']}\n\n"
            f"🔐 TLS: "
            f"{tls.get('tls_version', tls.get('error', 'Нет данных'))}\n"
            f"🌍 DNS IPv4: "
            f"{', '.join(dns.get('ipv4', [])) or 'Нет данных'}\n\n"
            f"📋 HTTP-заголовки:"
        )

        if "error" in headers:
            message += f"\nОшибка: {headers['error']}"
        else:
            for name, data in headers["headers"].items():
                status = "✅" if data["present"] else "❌"
                message += f"\n{status} {name}"

        await update.message.reply_text(message)

    except Exception:
        logger.exception("Site assessment failed")
        await update.message.reply_text(
            "Не удалось проверить сайт. "
            "Проверь адрес и попробуй ещё раз."
        )

def main() -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN")

    if not token:
        raise RuntimeError(
            "Установи переменную окружения TELEGRAM_BOT_TOKEN"
        )

    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, check_site)
    )

    app.run_polling()


if __name__ == "__main__":
    main()
