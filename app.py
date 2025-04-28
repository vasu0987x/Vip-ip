import asyncio
import logging
import threading
from flask import Flask
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, ContextTypes

# Settings
BOT_TOKEN = "8020708306:AAHmrEb8nkmBMzEEx_m88Nenyz5QgrQ85hA"
ADMIN_ID = 6972264549
LOG_CHANNEL = -1002522049841

# Flask app
app = Flask(__name__)

# Telegram Bot logic
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id != ADMIN_ID:
        await update.message.reply_text("Access Denied.")
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

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    if user_id != ADMIN_ID:
        await query.answer("Access Denied.")
        return
    await query.answer()
    choice = query.data
    await query.edit_message_text(f"You selected: {choice}\nComing soon...")

async def run_bot():
    bot_app = ApplicationBuilder().token(BOT_TOKEN).build()
    bot_app.add_handler(CommandHandler("start", start))
    bot_app.add_handler(CallbackQueryHandler(button_handler))
    await bot_app.start()
    await bot_app.updater.start_polling()
    await bot_app.idle()

def start_bot():
    asyncio.run(run_bot())

# Routes
@app.route('/')
def home():
    return "DarkIp Bot running! Health OK.", 200

# Main
if __name__ == "__main__":
    # Start Telegram bot in another thread
    threading.Thread(target=start_bot).start()
    # Start Flask server for Koyeb health check
    app.run(host="0.0.0.0", port=8080)
    
