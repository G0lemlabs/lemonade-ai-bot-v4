# Lemonade AI Bot v3 - 40 Component Token Scanner

A Telegram bot designed to scan token contracts for 40 different scam indicators and provide a detailed report. Built with Python using the `python-telegram-bot` library.

## Features
- Scans tokens for 40 scam components (e.g., Honeypot Check, High Buy Tax, etc.).
- Provides a score, verdict, and list of detected scam flags.
- Includes admin-only `/verify` command.
- Falls back to local simulation if the external API is unavailable.
- Supports retry logic for API connectivity issues.

## Prerequisites
- Python 3.8+
- Git (for cloning the repository)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/lemonade-ai-bot.git
   cd lemonade-ai-bot
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   Create a .env file in the root directory with the following:
   ```
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token
   SCAN_API_URL=your_scan_api_endpoint
   ADMIN_IDS=admin_user_id1,admin_user_id2
   ```

4. Run the bot:
   ```bash
   python app/lemonade_bot.py
   ```

## Usage

- `/start`: Displays a welcome message.
- `/scan <token>`: Scans the provided token for 40 scam components.
- `/verify <token>`: Marks a token as verified (admin only).

## Deployment

- Deploy to a platform like Architect by pushing to the linked Git repository.
- Monitor logs via the deployment dashboard.

## Contributing

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`.
3. Make changes and commit: `git commit -m "Add new feature"`.
4. Push to the branch: `git push origin feature-branch`.
5. Submit a pull request.

## License
[MIT License] - Feel free to modify and distribute.

## Contact
For issues or questions, open an issue on GitHub or contact the maintainer.
