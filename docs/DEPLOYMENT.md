# SafeBrowse X — Production Deployment & Operations Guide

This guide details deployment options for running SafeBrowse X in production environments.

---

## 🐳 Option 1: Docker Compose (Recommended)

The easiest way to deploy the complete SafeBrowse X ecosystem is via the provided `docker-compose.yml`:

```bash
# 1. Clone repository
git clone https://github.com/example/safebrowse-x.git
cd safebrowse-x

# 2. Configure environment
cp backend/.env.example backend/.env
# Edit backend/.env with your production database credentials and SECRET_KEY

# 3. Launch stack
docker-compose up --build -d
```

### Services Included
* **`api`**: FastAPI Backend (Port `8000`)
* **`dashboard`**: Nginx serving React Dashboard (Port `5173` or `80`)
* **`postgres`**: PostgreSQL 16 Alpine Database
* **`redis`**: Redis 7 Alpine Cache

---

## 💻 Option 2: Standalone Local / Bare Metal

### Backend Setup
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Run migrations and start server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Dashboard Setup
```bash
cd dashboard
npm install
npm run build
# Serve the ./dist directory with Nginx, Caddy, or serve:
npx serve -s dist -l 5173
```

---

## 🔄 Database Migrations & Initialization

Upon startup, the backend automatically initializes required schema tables using SQLAlchemy async engines. Default seed administrator credentials:
* **Email**: `admin@safebrowse.internal`
* **Password**: `AdminSafeBrowse2026!` *(Change immediately in production via Dashboard or API)*
