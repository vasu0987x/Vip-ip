import asyncio
import logging
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes
import requests

# --- Bot Settings ---
BOT_TOKEN = "8020708306:AAHmrEb8nkmBMzEEx_m88Nenyz5QgrQ85hA"
ADMIN_ID = 6972264549  # Only this user can use the bot
LOG_CHANNEL = -1002522049841  # Channel ID for logs

# --- Logging Setup ---
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# --- Start Command ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id != ADMIN_ID:
        await update.message.reply_text("Access Denied. You are not authorized to use DarkIp Bot.")
        return

    keyboard = [
        [InlineKeyboardButton("🌐 Scan Network", callback_data='scan_network')],
        [InlineKeyboardButton("🛡️ Scan Ports", callback_data='scan_ports')],
        [InlineKeyboardButton("🔍 Service Detection", callback_data='service_detection')],
        [InlineKeyboardButton("⚡ Attack", callback_data='attack')],
        [InlineKeyboardButton("🤖 Auto Attack Mode", callback_data='auto_attack')],
        [InlineKeyboardButton("📋 Report", callback_data='report')],
        [InlineKeyboardButton("❓ Help", callback_data='help')],
    ]

    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "Welcome to DarkIp Bot! Choose an action:",
        reply_markup=reply_markup
    )

# --- Button Handler ---
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id

    if user_id != ADMIN_ID:
        await query.answer("Access Denied.")
        return

    await query.answer()
    choice = query.data

    if choice == 'scan_network':
        await query.edit_message_text("Starting network scan... (Phase 2 under development)")
    elif choice == 'scan_ports':
        await query.edit_message_text("Starting port scan... (Phase 2 under development)")
    elif choice == 'service_detection':
        await query.edit_message_text("Starting service detection... (Phase 2 under development)")
    elif choice == 'attack':
        await query.edit_message_text("Preparing attack options... (Phase 2 under development)")
    elif choice == 'auto_attack':
        await query.edit_message_text("Auto Attack Mode activated... (Phase 2 under development)")
    elif choice == 'report':
        await query.edit_message_text("Fetching report... (Phase 2 under development)")
    elif choice == 'help':
        await query.edit_message_text("""
🌟 **DarkIp Bot Commands:**
- Scan Network
- Scan Ports
- Detect Services
- Attack Devices
- Auto Attack Mode
- Generate Reports

⚙️ Only authorized Admins can use the bot.
        """)

# --- Main ---
async def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))

    await app.start()
    print("DarkIp Bot is running...")
    await app.updater.start_polling()
    await app.idle()

if __name__ == "__main__":
    asyncio.run(main())
