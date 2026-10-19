# SheRise

SheRise is a Flask application backed by MySQL. Checkout uses Cash on Delivery (COD). Buyer support has a built-in FAQ fallback; the seller Business Assistant and Marketing Tool require a running local Ollama model and return an actionable error rather than fabricated AI output when it is unavailable.

## Local setup

1. Create a MySQL database and apply `database/she_rise_database.sql`.
2. Create and activate a virtual environment, then install dependencies:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and set the MySQL connection values. Set a unique `APP_SECRET_KEY` for persistent sessions. For production, set `APP_ENV=production` and use a random secret with at least 32 characters.
4. Provision the first administrator interactively:

   ```powershell
   flask --app app create-admin
   ```

5. Local AI for seller Business Assistant and Marketing Tool: install Ollama, download the model configured by `OLLAMA_MODEL` (default `llama3.2:3b`, for example `ollama pull llama3.2:3b`), and run Ollama locally. This uses no AI API fee, but requires local storage and compute. Buyer support can still answer common platform questions from its offline FAQ when Ollama is unavailable.
6. Start the application:

   ```powershell
   flask --app app run
   ```

Google OAuth is optional. Password sign-in works without Google credentials; OAuth requires a Google OAuth client and a callback URL configured in `.env`.

The seller Business Assistant covers pricing, inventory, customer communication, scheme discovery, roadmaps, finance, planning and marketing guidance. The Marketing Tool generates nine selectable text formats from saved seller products or manually supplied details. Poster and banner options return copy and layout guidance, not images. Successful generated results are recorded per seller and the latest result is restored when the tool is reopened.

## Payment and external resources

The application does not use an online payment gateway. Buyers pay cash on delivery. Return approval records the administrator's decision but does not issue a refund; COD refunds must be handled manually.

Google Fonts and Font Awesome are loaded from their public CDNs on a few mentor pages. They do not require an API key or payment, but those pages need internet access to load the custom fonts/icons. Google OAuth is an optional external sign-in integration. Ollama is local; the FAQ fallback makes no external AI request.
