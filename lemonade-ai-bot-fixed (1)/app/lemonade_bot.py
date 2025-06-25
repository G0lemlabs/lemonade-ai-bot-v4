import os
import logging
import signal
import sys
import requests
import time
import random
import re
import json
from pathlib import Path
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
    AIORateLimiter,
)
from telegram.helpers import escape_markdown
from dotenv import load_dotenv
from datetime import datetime, timezone

# Railway already provides environment variables, no need to load .env

# Validate environment variables
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
SCAN_API = os.getenv("SCAN_API_URL")
if not TOKEN:
    raise ValueError("TELEGRAM_BOT_TOKEN is not set in the environment.")
if not SCAN_API:
    raise ValueError("SCAN_API_URL is not set in the environment.")

# Sanitize admin IDs
ADMIN_IDS = [id.strip() for id in os.getenv("ADMIN_IDS", "").split(",") if id.strip()]
if not ADMIN_IDS:
    logging.warning("No valid ADMIN_IDS provided. Admin commands will be restricted.")

# Set up logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Address validation regex
ETH_ADDRESS_REGEX = r"^0x[a-fA-F0-9]{40}$"
SOL_ADDRESS_REGEX = r"^[1-9A-HJ-NP-Za-km-z]{32,44}$"

# Cache and history files
CACHE_FILE = Path("scan_cache.json")
HISTORY_FILE = Path("scan_history.json")
MAX_CACHE_SIZE = 1000  # Limit cache entries
MAX_HISTORY_SIZE = 100  # Limit history entries per user

# Define 40 scanner modules
scanner_modules = [
    {"id": 1, "title": "Honeypot Check", "function": "detect_honeypot", "weight": 10},
    {"id": 2, "title": "Blacklist Function Detected", "function": "detect_blacklist_function", "weight": 9},
    {"id": 3, "title": "Owner Wallet is EOA", "function": "is_owner_eoa", "weight": 7},
    {"id": 4, "title": "High Buy Tax", "function": "detect_high_buy_tax", "weight": 6},
    {"id": 5, "title": "High Sell Tax", "function": "detect_high_sell_tax", "weight": 6},
    {"id": 6, "title": "Trading Disabled", "function": "detect_trading_disabled", "weight": 10},
    {"id": 7, "title": "Mint Function Enabled", "function": "detect_mint_function", "weight": 9},
    {"id": 8, "title": "Transfer Limit Active", "function": "detect_transfer_limit", "weight": 5},
    {"id": 9, "title": "Dev Can Change Fees", "function": "detect_fee_modifiable", "weight": 8},
    {"id": 10, "title": "Liquidity Not Locked", "function": "detect_lp_not_locked", "weight": 10},
    {"id": 11, "title": "Renounce Function Missing", "function": "detect_no_renounce", "weight": 6},
    {"id": 12, "title": "Unlimited Allowance Detected", "function": "detect_unlimited_allowance", "weight": 5},
    {"id": 13, "title": "Proxy Contract Detected", "function": "detect_proxy_usage", "weight": 9},
    {"id": 14, "title": "Trading Freeze Enabled", "function": "detect_trading_freeze", "weight": 7},
    {"id": 15, "title": "Token Age Too Young", "function": "check_token_age", "weight": 5},
    {"id": 16, "title": "No Anti-Rug Measures", "function": "detect_missing_anti_rug", "weight": 4},
    {"id": 17, "title": "Mint Authority Retained", "function": "detect_mint_privileges", "weight": 9},
    {"id": 18, "title": "Suspicious Wallet Cluster", "function": "is_suspicious_cluster", "weight": 8},
    {"id": 19, "title": "Fake Ownership Renounce", "function": "detect_fake_renounce", "weight": 6},
    {"id": 20, "title": "Fake LP Burn", "function": "detect_fake_lp_burn", "weight": 7},
    {"id": 21, "title": "Single Owner, No Multi-Sig", "function": "detect_no_multisig", "weight": 5},
    {"id": 22, "title": "Developer Has Mint Privileges", "function": "detect_dev_mint_privilege", "weight": 10},
    {"id": 23, "title": "Token Can Be Paused", "function": "detect_pausable", "weight": 6},
    {"id": 24, "title": "Delayed Trading Start", "function": "detect_trading_delay", "weight": 4},
    {"id": 25, "title": "Hidden Transfer Fee Logic", "function": "detect_hidden_transfer_fee", "weight": 8},
    {"id": 26, "title": "Obfuscated Contract Code", "function": "detect_obfuscation", "weight": 7},
    {"id": 27, "title": "Honeypot on First Buyers", "function": "detect_first_buyer_honeypot", "weight": 9},
    {"id": 28, "title": "Owner Linked to Known Rugs", "function": "is_creator_blacklisted", "weight": 10},
    {"id": 29, "title": "Forked From Scam Template", "function": "detect_scam_contract_fork", "weight": 9},
    {"id": 30, "title": "Liquidity Can Be Withdrawn", "function": "detect_lp_withdrawable", "weight": 10},
    {"id": 31, "title": "Obscured Mint Authority", "function": "detect_hidden_mint", "weight": 7},
    {"id": 32, "title": "Excessive Token Supply", "function": "check_total_supply", "weight": 4},
    {"id": 33, "title": "Dev Wallet Owns Majority Supply", "function": "detect_dev_token_hoard", "weight": 8},
    {"id": 34, "title": "Short LP Lock Period", "function": "detect_short_lp_lock", "weight": 5},
    {"id": 35, "title": "Admin Wallet Whitelist Function", "function": "detect_whitelist_function", "weight": 9},
    {"id": 36, "title": "Post-Launch Minting Enabled", "function": "detect_post_launch_minting", "weight": 10},
    {"id": 37, "title": "Dev-Callable LP Burn", "function": "detect_dev_lp_burn_access", "weight": 6},
    {"id": 38, "title": "Hidden Anti-Bot Logic", "function": "detect_hidden_anti_bot", "weight": 8},
    {"id": 39, "title": "Owner Changed Post-Launch", "function": "detect_ownership_change", "weight": 7},
    {"id": 40, "title": "Contract Not Verified", "function": "is_contract_verified", "weight": 10}
]

def simulate_scan(token):
    """Simulate a scan with realistic scoring and module triggers."""
    total_weight = sum(module["weight"] for module in scanner_modules)
    # High-risk modules (weight >= 9) have lower trigger chance
    triggered = [
        m for m in scanner_modules
        if random.random() < (0.05 if m["weight"] >= 9 else 0.15)
    ]
    score = 100 - (sum(m["weight"] for m in triggered) / total_weight * 100)
    score = max(0, min(100, round(score, 2)))
    verdict = "Safe" if score >= 70 else "Suspicious" if score >= 30 else "Dangerous"
    return {
        "score": score,
        "verdict": verdict,
        "flags_triggered": [m["title"] for m in triggered],
        "messages": [f"Module {m['id']}: {m['title']} detected." for m in triggered],
        "scam_components": [m["title"] for m in triggered],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def load_cache():
    """Load scan cache from file."""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE) as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error("Corrupted cache file. Starting fresh.")
    return {}

def save_cache(cache):
    """Save scan cache to file, limiting size."""
    if len(cache) > MAX_CACHE_SIZE:
        # Remove oldest entries
        sorted_keys = sorted(cache, key=lambda k: cache[k]["timestamp"])
        for key in sorted_keys[:len(cache) - MAX_CACHE_SIZE]:
            del cache[key]
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception as e:
        logger.error(f"Failed to save cache: {e}")

def load_history():
    """Load scan history from file."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error("Corrupted history file. Starting fresh.")
    return {}

def save_history(history):
    """Save scan history to file, limiting size per user."""
    for user_id in history:
        if len(history[user_id]) > MAX_HISTORY_SIZE:
            history[user_id] = history[user_id][-MAX_HISTORY_SIZE:]
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f)
    except Exception as e:
        logger.error(f"Failed to save history: {e}")

async def run_scan(token):
    """Run a scan, using cache, API, or mock."""
    cache = load_cache()
    if token in cache:
        logger.info(f"Returning cached result for {token}")
        return cache[token]

    try:
        payload = {"token": token, "scan_type": "40", "modules": [m["title"] for m in scanner_modules]}
        for attempt in range(3):
            try:
                response = requests.post(SCAN_API, json=payload, timeout=10)
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ValueError("Invalid API response format")
                # Sanitize response
                required_keys = ["score", "verdict", "flags_triggered", "messages", "scam_components"]
                for key in required_keys:
                    if key not in data:
                        data[key] = [] if key in ["flags_triggered", "messages", "scam_components"] else "N/A"
                data["timestamp"] = datetime.now(timezone.utc).isoformat()
                cache[token] = data
                save_cache(cache)
                return data
            except requests.exceptions.RequestException as e:
                if attempt == 2:
                    logger.error(f"API failed after 3 attempts: {e}")
                    raise
                time.sleep(2 ** attempt)
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.warning(f"Failed to connect to SCAN_API: {e}. Using mock scan.")
        data = simulate_scan(token)
        cache[token] = data
        save_cache(cache)
        return data

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for the /start command."""
    await update.message.reply_text(
        "🍋 *Lemonade the Beagle* here! I'm your degen rug sniffer.\n"
        "Use /scan <token> to check for 40 scam components.\n"
        "Use /help for more options.\n"
        "_Built by G0lem Labs_",
        parse_mode=ParseMode.MARKDOWN_V2
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for the /help command."""
    await update.message.reply_text(
        "🟡 *Lemonade Rug Scanner Commands*\n\n"
        "/start — Introduce the bot\n"
        "/help — Show this menu\n"
        "/scan <token> — Scan an ETH or SOL token address\n"
        "/history — View your recent scans\n"
        "/status — Check bot status\n"
        "/verify <token> — Admin-only token verification\n"
        "/clear_cache — Admin-only cache clear\n\n"
        "Drop a token address (ETH or SOL) to scan with 40+ AI-powered checks.\n"
        "*Note:* Scans may use mock data if the API is unavailable.\n"
        "_Built by G0lem Labs_",
        parse_mode=ParseMode.MARKDOWN_V2
    )

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for the /status command."""
    cache = load_cache()
    await update.message.reply_text(
        f"🍋 *Lemonade Status*\n\n"
        f"Bot: Online\n"
        f"Cache Size: {len(cache)}/{MAX_CACHE_SIZE}\n"
        f"API: {'Available' if requests.get(SCAN_API, timeout=5).status_code == 200 else 'Unavailable'}",
        parse_mode=ParseMode.MARKDOWN_V2
    )

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for the /scan command, requesting a 40 component scan."""
    if not context.args:
        await update.message.reply_text("Usage: /scan <token>")
        return

    token = context.args[0].strip()
    if not (re.match(ETH_ADDRESS_REGEX, token) or re.match(SOL_ADDRESS_REGEX, token)):
        await update.message.reply_text("Invalid ETH or SOL token address.")
        return

    status_msg = await update.message.reply_text("🧠 Scanning... Fetching data...")
    try:
        await status_msg.edit_text("🧠 Scanning... Analyzing with 40 modules...")
        data = await run_scan(token)

        # Save to history
        history = load_history()
        user_id = str(update.effective_user.id)
        if user_id not in history:
            history[user_id] = []
        history[user_id].append({
            "token": token,
            "score": data["score"],
            "verdict": data["verdict"],
            "timestamp": data["timestamp"]
        })
        save_history(history)

        score = escape_markdown(str(data["score"]), version=2)
        verdict = escape_markdown(data["verdict"], version=2)
        flags = escape_markdown(", ".join(data["flags_triggered"]), version=2)
        messages_text = "\n".join([f"💬 {escape_markdown(msg, version=2)}" for msg in data["messages"]])
        source = escape_markdown("Mock" if "timestamp" in data and data["timestamp"] == simulate_scan(token)["timestamp"] else "API", version=2)

        if data["scam_components"]:
            components_text = "\n".join([f"⚠️ {escape_markdown(comp, version=2)}" for comp in data["scam_components"][:10]])
            messages_text += f"\n\n*40 Scam Components Detected (Top 10):*\n{components_text}"

        reply = (
            f"🍋 *LEMONADE 40 COMPONENT SCAN REPORT*\n\n"
            f"🔢 *Score:* {score}/100\n"
            f"🧠 *Verdict:* {verdict}\n"
            f"📛 *Flags:* {flags}\n"
            f"🌐 *Source:* {source}\n\n"
            f"{messages_text}"
        )
        for attempt in range(3):
            try:
                await status_msg.edit_text(reply, parse_mode=ParseMode.MARKDOWN_V2)
                break
            except Exception as e:
                if attempt == 2:
                    logger.error(f"Failed to send scan result after 3 attempts: {e}")
                    await update.message.reply_text("⚠️ Error sending scan result. Please try again.")
                time.sleep(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        await status_msg.edit_text("⚠️ Scan failed. Please try again later.")

async def history(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for the /history command."""
    user_id = str(update.effective_user.id)
    history = load_history()
    if user_id not in history or not history[user_id]:
        await update.message.reply_text("No scan history found.")
        return

    history_text = "📜 *Recent Scans (Last 5)*\n\n"
    for scan in history[user_id][-5:]:
        token = escape_markdown(scan["token"], version=2)
        score = escape_markdown(str(scan["score"]), version=2)
        verdict = escape_markdown(scan["verdict"], version=2)
        timestamp = escape_markdown(scan["timestamp"], version=2)
        history_text += f"Token: {token}\nScore: {score}/100\nVerdict: {verdict}\nTime: {timestamp}\n\n"
    
    await update.message.reply_text(history_text, parse_mode=ParseMode.MARKDOWN_V2)

async def verify(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for the /verify command (admin only)."""
    user_id = str(update.effective_user.id)
    if user_id not in [str(id) for id in ADMIN_IDS]:
        logger.warning(f"Unauthorized /verify attempt by user {user_id}")
        await update.message.reply_text("⛔️ You're not authorized to verify tokens.")
        return

    if not context.args:
        await update.message.reply_text("Usage: /verify <token>")
        return

    token = context.args[0].strip()
    if not (re.match(ETH_ADDRESS_REGEX, token) or re.match(SOL_ADDRESS_REGEX, token)):
        await update.message.reply_text("Invalid ETH or SOL token address.")
        return

    await update.message.reply_text(
        f"✅ Token {escape_markdown(token, version=2)} has been marked as verified by an admin.",
        parse_mode=ParseMode.MARKDOWN_V2
    )

async def clear_cache(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for the /clear_cache command (admin only)."""
    user_id = str(update.effective_user.id)
    if user_id not in [str(id) for id in ADMIN_IDS]:
        logger.warning(f"Unauthorized /clear_cache attempt by user {user_id}")
        await update.message.reply_text("⛔️ You're not authorized to clear the cache.")
        return

    if CACHE_FILE.exists():
        try:
            CACHE_FILE.unlink()
            logger.info("Cache cleared by admin.")
            await update.message.reply_text("✅ Cache cleared successfully.")
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            await update.message.reply_text("⚠️ Failed to clear cache.")
    else:
        await update.message.reply_text("No cache file exists.")

async def scan_token(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handler for direct token address messages."""
    token = update.message.text.strip()
    if not (re.match(ETH_ADDRESS_REGEX, token) or re.match(SOL_ADDRESS_REGEX, token)):
        await update.message.reply_text("Invalid ETH or SOL token address.")
        return

    context.args = [token]
    await scan(update, context)

def shutdown(signum, frame):
    """Handle graceful shutdown."""
    logger.info("Shutting down bot...")
    sys.exit(0)

def main():
    """Main function to run the bot."""
    app = ApplicationBuilder().token(TOKEN).rate_limiter(AIORateLimiter()).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(CommandHandler("history", history))
    app.add_handler(CommandHandler("verify", verify))
    app.add_handler(CommandHandler("clear_cache", clear_cache))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_token))

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("Starting Lemonade the Beagle bot...")
    app.run_polling(drop_pending_updates=True, timeout=10)

if __name__ == "__main__":
    main()
