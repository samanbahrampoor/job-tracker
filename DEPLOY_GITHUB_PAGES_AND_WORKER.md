# Deploy: GitHub Pages + Cloudflare Worker (GitHub OAuth gated)

## 1) GitHub Pages
- Put `jobs.html` in your repo. Enable Pages in Settings → Pages.
- Edit `jobs.html`, set `WORKER_BASE` to your Worker URL.

## 2) Cloudflare Worker
```bash
npm i -g wrangler
wrangler login
wrangler kv:namespace create JOBS_KV
```
Update `wrangler.toml` with the KV id and vars:
- `ALLOWED_LOGIN` (your GitHub username)
- `ALLOWED_ORIGIN` (https://yourname.github.io)
- `PUBLIC_URL` (your worker URL)

Set secrets and deploy:
```bash
wrangler secret put GITHUB_CLIENT_ID
wrangler secret put GITHUB_CLIENT_SECRET
wrangler secret put SESSION_SECRET
wrangler deploy
```

## 3) Data
Export `jobs.json` from Excel:
```bash
python update_webpage_from_excel.py
```
Upload to KV:
```bash
wrangler kv:key put --binding=JOBS_KV jobs.json --path=jobs.json
```

Open your Pages URL → **Sign in with GitHub** → data loads privately.
