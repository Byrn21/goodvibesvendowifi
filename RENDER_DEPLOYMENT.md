# Render.com Deployment Guide

Deploy your Omada captive portal backend to **Render.com** — PostgreSQL database, Docker containerization, automatic HTTPS, and free tier available.

---

## ✅ What You Get (Free Tier)

- **Free PostgreSQL database** (0.5 GB storage, 0.5 GB RAM)
- **Free web service** (512 MB RAM, 0.5 vCPU, sleeps after 15 min of inactivity)
- **Automatic HTTPS** with Render-provided certificate
- **Custom domains** supported
- **Auto-deploy on push** to `main` branch
- **Managed database** with backups and failover

---

## 🚀 Quick Deployment

### **Option 1: One-Click Deploy (Recommended)**

1. Go to [https://dashboard.render.com](https://dashboard.render.com)
2. Click **"New +"** → **"Blueprint"**
3. Connect your GitHub repository
4. Render auto-detects `render.yaml` at the repository root
5. Review the pre-configured services (web service + PostgreSQL database)
6. Click **"Deploy"**

Render provisions the database and builds your Docker container in 2-4 minutes.

### **Option 2: Manual Web Service**

1. Go to [https://dashboard.render.com](https://dashboard.render.com)
2. Click **"New +"** → **"Web Service"**
3. Connect your GitHub repository
4. Configure:

```
Name: goodvibesvendowifi
Region: Oregon (or closest to you)
Branch: main
Environment: Docker
Dockerfile path: backend/Dockerfile
Build command: (auto-detect from Dockerfile)
Start command: npm start
```

### **Option 3: Manual + Separate Database**

1. Deploy web service as above (skip database auto-creation)
2. Click **"New +"** → **"PostgreSQL"** → **"Create database"**
3. Name it `postgres` (or your preferred name)
4. Link the database to your web service under **"Environment" → "Add Environment Variable"**:

```
Key: DATABASE_URL
Value: (from database connection string)
```

---

## 🔐 Required Environment Variables

After deployment (or during manual setup), set these secrets in the **Render Dashboard → Your Service → Environment → Environment Variables**:

```bash
# --- Application URLs ---
# Set after first deploy; find your URL in the Render dashboard
BASE_URL=https://goodvibesvendowifi.onrender.com
FRONTEND_ORIGIN=https://your-frontend-url.pages.dev

# --- Omada Controller ---
OMADA_BASE_URL=https://192.168.1.252:8043
OMADA_API_TOKEN=your-controller-api-token-here
OMADA_SITE=Default

# --- Security ---
JWT_SECRET=<GENERATE_RANDOM_STRING_HERE>
CORS_ORIGINS=https://your-frontend-url.pages.dev

```

> **Note:** `DATABASE_URL` is automatically set by Render from your PostgreSQL add-on. `PG_SSL_REJECT_UNAUTHORIZED=false` is also pre-configured in `render.yaml` for Render's PostgreSQL TLS handling.

---

## 🗄️ Database Migration & Seeding

### Automatic (via `render.yaml`)

The `render.yaml` file includes an optional migration step. If you need to run migrations manually:

### Manual Migration

1. After the database is attached, go to your service in the Render dashboard
2. Click **"Shell"** tab
3. Run:

```bash
# Navigate to backend directory
cd /app

# Run migrations (applies schema.sql to PostgreSQL)
node src/db/migrate.js

# Seed development vouchers (OPTIONAL — dev only, do NOT run in production)
NODE_ENV=development node src/db/seed.js
```

> **Note:** If `DATABASE_URL` is not set in your shell environment, it is automatically injected by Render from your PostgreSQL add-on. For local development, use `DATABASE_URL=sqlite:./data/portal.db`.

---

## 🔧 Local Development Setup

For local development, the backend uses **SQLite** — no PostgreSQL needed locally.

```bash
cd backend

# Install dependencies
npm install

# Copy env template
cp .env.example .env

# Local development uses SQLite by default
# The DATABASE_URL in .env.example contains the SQLite fallback:
DATABASE_URL=sqlite:./data/portal.db

# Run migrations locally
npm run db:migrate

# Start in development mode (auto-reload with nodemon)
npm run dev
```

The server starts on `http://localhost:3000` by default.

---

## 🌐 Post-Deployment Configuration

### **1. Update Frontend Config**

Edit `config/config.js` and set your Render backend URL:

```javascript
apiBaseUrl: 'https://goodvibesvendowifi.onrender.com',
```

### **2. Generate JWT Secret**

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Paste the output into the `JWT_SECRET` environment variable in the Render dashboard.

### **3. Test Your Backend**

```bash
# Health check
curl https://goodvibesvendowifi.onrender.com/api/health

# Expected response:
# {"success":true,"message":"Server is healthy"}
```

---

## 🔄 Auto-Deploy on Git Push

Render automatically builds and deploys when you push to `main`:

```bash
git add .
git commit -m "Update backend"
git push origin main
# Render auto-deploys in 2-4 minutes ✅
```

---

## 📊 Monitoring & Logs

### View Logs

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Select your service
3. Click **"Logs"** tab — real-time logs appear here

### Check Metrics

- CPU usage
- Memory usage
- Request count
- Response times

All visible in the **"Metrics"** tab.

---

## 🛠️ Troubleshooting

### **Issue: "Database connection refused"**

**Cause**: The `DATABASE_URL` environment variable is not set or incorrect.

**Fix**: Ensure your web service has a PostgreSQL database attached. In the Render dashboard, check **"Environment"** → **`DATABASE_URL`** is populated. If not, add/reattach the PostgreSQL database add-on.

### **Issue: "Cannot connect to Omada Controller"**

**Cause**: Your Omada controller is on a local network; Render cannot reach it directly.

**Solutions**:
1. **Use `OMADA_MOCK=true`** for testing without a controller
2. **Expose your controller** with a secure tunnel (e.g., Cloudflare Tunnel, Tailscale) — ensure HTTPS and that the Omada API port is reachable from Render's IP ranges
3. **On-premise deployment**: Use Docker Compose locally if your controller is on-premises

### **Issue: CORS errors in browser**

**Fix**: Update `CORS_ORIGINS` in the Render dashboard to match your frontend URL exactly. For example:

```
CORS_ORIGINS=https://captive.yourdomain.com
```

### **Issue: Service sleeping / slow first request**

**Cause**: Render's free tier web service sleeps after 15 minutes of inactivity, causing a cold start on the next request.

**Fix**: Upgrade to a paid **"Starter"** plan ($7/month) for always-on service.

---

## 💰 Cost Breakdown (Free Tier)

| Resource | Render Free Tier | Cost |
|----------|-----------------|------|
| Web Service | 512 MB RAM, 0.5 vCPU | **$0** |
| PostgreSQL Database | 0.5 GB RAM, 0.5 GB disk | **$0** |
| Custom Domain | Yes | **$0** |
| HTTPS | Automatic | **$0** |
| **Total** | | **$0/month** |

**Free tier limitations**:
- Web service sleeps after 15 min idle (cold starts)
- 100 GB bandwidth limit per month
- 0.5 GB database storage (sufficient for thousands of sessions)
- No custom cron schedules on free tier

Upgrade to **Starter** ($7/month) for always-on web service and more resources.

---

## 📚 Additional Resources

- [Render Documentation](https://render.com/docs)
- [Render PostgreSQL Guide](https://render.com/docs/databases)
- [Deploy Node.js on Render](https://render.com/docs/deploy-node-express-app)
- [Community Support](https://community.render.com)

---

## 🎯 Next Steps

1. ✅ Backend deployed on Render with PostgreSQL
2. ⬜ Deploy frontend to Cloudflare Pages / GitHub Pages
3. ⬜ Configure Omada controller to use your captive portal
4. ⬜ Update `config/config.js` with your Render backend URL
5. ⬜ Set all secrets in the Render dashboard
6. ⬜ Run database migration: `node src/db/migrate.js`
7. ⬜ Test end-to-end with a voucher

---

## 📁 Project File Reference

| File | Purpose |
|------|---------|
| `render.yaml` | Render Blueprint definition (web service + PostgreSQL) |
| `backend/Dockerfile` | Docker container for the Node.js backend |
| `backend/src/db/client.js` | Dual-mode DB client (SQLite dev / PostgreSQL prod) |
| `backend/src/db/migrate.js` | Migration runner — applies `schema.sql` |
| `backend/src/db/seed.js` | Development seed script for sample vouchers |
| `backend/src/db/schema.sql` | SQL schema (PostgreSQL + SQLite compatible) |
| `backend/.env.example` | Local development environment template |
| `backend/package.json` | Node.js dependencies and scripts |
| `config/config.js` | Frontend configuration (update `apiBaseUrl` to your Render URL) |

---