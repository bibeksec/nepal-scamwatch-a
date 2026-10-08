# Nepal ScamWatch (Cloudflare Worker + D1 + R2)

## Setup (once)
```bash
npm install
npx wrangler login

npx wrangler d1 create nepal-scamwatch-db     # copy database_id into wrangler.toml
npx wrangler r2 bucket create nepal-scamwatch-evidence

npx wrangler d1 migrations apply nepal-scamwatch-db --remote

openssl rand -hex 32                          # generate a token
npx wrangler secret put ADMIN_TOKEN           # paste it (needs the Worker deployed once, see below)

npx wrangler deploy
```
If `secret put` complains the Worker doesn't exist yet, run `npx wrangler deploy` first, then `secret put`.
<img width="1853" height="925" alt="Screenshot from 2026-10-08 10-30-30" src="https://github.com/user-attachments/assets/e8b60024-7406-496d-aace-eaae20121266" />
https://nepal-scamwatch.bibektamata012.workers.dev/
## Pages
- `/`            public site
- `/admin.html`  moderation panel (enter your ADMIN_TOKEN)
<img width="1871" height="931" alt="Screenshot from 2026-10-08 10-29-30" src="https://github.com/user-attachments/assets/1df08278-3624-441c-8213-0ce1f0bcbe80" />
https://nepal-scamwatch.bibektamata012.workers.dev/admin
## Local testing
Create `.dev.vars` containing `ADMIN_TOKEN=test123`, then:
```bash
npm run migrate:local
npm run dev
```
