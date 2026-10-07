# soc-triage
AI-assisted SOC alert triage and incident prioritization platform

## Docker Setup (PostgreSQL)

You can run the backend and the PostgreSQL database easily via Docker Compose.

1. Create a `.env` file based on the example:
   ```bash
   cd backend
   copy .env.example .env
   ```
   (Make sure to edit `.env` and set `DATABASE_URL` to point to the `db` service if you want to use Postgres, e.g. `postgresql+psycopg://soc_user:soc_password@db:5432/soc_db`)

2. Start the services:
   ```bash
   docker-compose up --build -d
   ```

3. The API will be available at `http://localhost:8000`.

## Local Development (SQLite)

If you prefer to run it locally without Docker:
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

## Frontend Setup

The frontend is built with Next.js and Tailwind CSS.

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   npm install
   ```
2. Start the development server:
   ```bash
   npm run dev
   ```
3. Open `http://localhost:3000` in your browser.

## Playwright End-to-End Tests
To run the automated smoke tests across multiple responsive viewports:
```bash
cd frontend
npx playwright test
```
