# Deploying BastionWAF to Render (Step-by-Step Guide)

BastionWAF is pre-configured with a **Render Blueprint (`render.yaml`)** and an optimized production **`Dockerfile`**. You can deploy it to Render in just a few clicks.

---

## Prerequisites
1. A free account on [Render](https://render.com).
2. Your BastionWAF repository pushed to **GitHub** or **GitLab**.

---

## Method 1: Deploy with 1 Click using Render Blueprint (Recommended)

1. Log into your **[Render Dashboard](https://dashboard.render.com)**.
2. Click **New +** in the top right, then select **Blueprint**.
3. Connect your GitHub/GitLab repository (`FinsterNet/BastionWAF`).
4. Render will automatically detect the **`render.yaml`** file in your repo:
   - **Service Name**: `bastion-waf`
   - **Runtime**: `Docker`
   - **Plan**: `Free` (or Starter)
   - **Health Check**: `/healthz`
   - **Environment Variables**: Pre-configured (`PORT=10000`, `BASTION_HOST=0.0.0.0`)
5. Click **Apply**.
6. Render will build the Docker container and deploy it in ~1–2 minutes.
7. Once deployed, Render provides a public HTTPS URL:
   ```text
   https://bastion-waf.onrender.com
   ```

---

## Method 2: Manual Web Service Setup

If you prefer to configure it manually without the Blueprint:

1. In the Render Dashboard, click **New +** -> **Web Service**.
2. Connect your repository.
3. Configure the following fields:
   - **Name**: `bastion-waf`
   - **Region**: Choose the region closest to your users (e.g. `Oregon`, `Frankfurt`)
   - **Language / Runtime**: `Docker`
   - **Dockerfile Path**: `./Dockerfile`
   - **Docker Build Context**: `.`
   - **Instance Type**: `Free` (or higher)
4. Under **Advanced Settings**:
   - **Health Check Path**: `/healthz`
5. Click **Create Web Service**.

---

## Verifying Your Live Deployment

### 1. Test Health Check
Open your browser or run:
```bash
curl https://bastion-waf.onrender.com/healthz
```
Expected Response:
```json
{"status": "healthy", "service": "bastion-waf", "mode": "active"}
```

### 2. Test WAF Active Threat Blocking
Test sending a simulated SQL Injection payload:
```bash
curl -i "https://bastion-waf.onrender.com/search?q=%27+OR+%271%27%3D%271"
```
Expected Response:
```text
HTTP/2 403 Forbidden
{"blocked": true, "rule": "942100", "reason": "SQL syntax pattern detected", "status": 403}
```

---

## Routing Your Real Application Traffic

To protect your backend application (e.g. an API, WordPress, Node.js app, or Vercel site):

1. Edit [`waf/config/bastion.yaml`](waf/config/bastion.yaml):
   ```yaml
   sites:
     - domain: "bastion-waf.onrender.com"
       upstream: "https://your-backend-app.com"
       defense_mode: true
   ```
2. Commit and push to git:
   ```bash
   git add waf/config/bastion.yaml
   git commit -m "Update upstream backend site"
   git push
   ```
3. Render will automatically redeploy with zero downtime!
