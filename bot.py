
import os
import logging

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
        result = run_assessment(target)

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
