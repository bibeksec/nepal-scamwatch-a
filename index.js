const CATEGORIES = ["Sextortion","Video Call Scam","Investment Fraud","Marketplace Fraud","Fake Employment","Phishing","Romance Scam","Other"];
const PLATFORMS = ["Facebook","Instagram","WhatsApp","Telegram","TikTok","Website","Marketplace","Other"];
const RISKS = ["Low","Medium","High"];
const STATUSES = ["pending","approved","corroborated","rejected"];
const MAX_BYTES = 1024 * 1024; // D1 rows max out at ~2 MB, base64 adds ~33%
const MAX_REPORTS_PER_HOUR = 5;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=UTF-8", "cache-control": "no-store" },
  });

const clean = (v, max = 5000) => (typeof v === "string" ? v.trim().slice(0, max) : "");

const sha256 = async (text) => {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
};

async function isAdmin(request, env) {
  if (!env.ADMIN_TOKEN) return false;
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return false;
  // Compare hashes so comparison time doesn't leak the token
  const [a, b] = await Promise.all([sha256(auth.slice(7)), sha256(env.ADMIN_TOKEN)]);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function generateCaseId() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return `NSW-${new Date().getUTCFullYear()}-${String(n).padStart(6, "0")}`;
}

// Detect real image type from file bytes (don't trust the browser's claim)
async function sniffImage(file) {
  const b = new Uint8Array(await file.slice(0, 12).arrayBuffer());
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return { type: "image/jpeg", ext: "jpg" };
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return { type: "image/png", ext: "png" };
  const riff = String.fromCharCode(...b.slice(0, 4));
  const webp = String.fromCharCode(...b.slice(8, 12));
  if (riff === "RIFF" && webp === "WEBP") return { type: "image/webp", ext: "webp" };
  return null;
}

function toBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}
function fromBase64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const publicEvidenceUrl = (key) =>
  key && key.startsWith("public/") ? "/evidence/" + encodeURIComponent(key.slice(7)) : null;

/* ---------------- PUBLIC ---------------- */

async function listPublic(request, env) {
  const url = new URL(request.url);
  const search = clean(url.searchParams.get("search"), 100);
  const category = clean(url.searchParams.get("category"), 100);

  let sql = `SELECT case_id,title,category,platform,identifier,description,risk,status,evidence_key,created_at
             FROM reports WHERE status IN ('approved','corroborated')`;
  const params = [];

  if (search) {
    const q = "%" + search.replace(/[\\%_]/g, "\\$&") + "%";
    sql += ` AND (case_id LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' OR category LIKE ? ESCAPE '\\'
             OR platform LIKE ? ESCAPE '\\' OR identifier LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')`;
    params.push(q, q, q, q, q, q);
  }
  if (category && category !== "All") {
    sql += ` AND category = ?`;
    params.push(category);
  }
  sql += ` ORDER BY created_at DESC LIMIT 100`;

  const { results } = await env.DB.prepare(sql).bind(...params).all();
  const reports = results.map(({ evidence_key, ...r }) => ({ ...r, evidence_url: publicEvidenceUrl(evidence_key) }));
  return json({ success: true, reports });
}

async function stats(env) {
  const r = await env.DB.prepare(`
    SELECT
      SUM(CASE WHEN status IN ('approved','corroborated') THEN 1 ELSE 0 END) AS total,
      SUM(CASE WHEN status IN ('approved','corroborated') AND category IN ('Sextortion','Video Call Scam') THEN 1 ELSE 0 END) AS sextortion,
      SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
      SUM(CASE WHEN status = 'corroborated' THEN 1 ELSE 0 END) AS corroborated
    FROM reports`).first();
  return json({
    success: true,
    stats: {
      total: r?.total || 0,
      sextortion: r?.sextortion || 0,
      pending: r?.pending || 0,
      corroborated: r?.corroborated || 0,
    },
  });
}

async function createReport(request, env) {
  let form;
  try { form = await request.formData(); }
  catch { return json({ success: false, error: "Invalid form data." }, 400); }

  // Honeypot: real users never fill this hidden field
  if (clean(form.get("website_url"), 200)) {
    return json({ success: true, message: "Report submitted for moderation.", case_id: "NSW-0000-000000", status: "pending" }, 201);
  }

  const title = clean(form.get("title"), 150);
  const category = clean(form.get("category"), 100);
  const platform = clean(form.get("platform"), 100);
  const identifier = clean(form.get("identifier"), 200);
  const description = clean(form.get("description"), 5000);
  const risk = clean(form.get("risk"), 20) || "Medium";

  if (!title || !category || !platform || !description)
    return json({ success: false, error: "Title, category, platform and description are required." }, 400);
  if (description.length < 20)
    return json({ success: false, error: "Please describe the incident in a little more detail." }, 400);
  if (!CATEGORIES.includes(category)) return json({ success: false, error: "Invalid category." }, 400);
  if (!PLATFORMS.includes(platform)) return json({ success: false, error: "Invalid platform." }, 400);
  if (!RISKS.includes(risk)) return json({ success: false, error: "Invalid risk level." }, 400);

  // Simple per-IP rate limit
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipHash = await sha256("nsw-salt:" + ip);
  const since = new Date(Date.now() - 3600 * 1000).toISOString();
  const recent = await env.DB.prepare(`SELECT COUNT(*) AS c FROM reports WHERE ip_hash = ? AND created_at > ?`)
    .bind(ipHash, since).first();
  if ((recent?.c || 0) >= MAX_REPORTS_PER_HOUR)
    return json({ success: false, error: "Too many reports from your network. Please try again later." }, 429);

  // Evidence image (optional)
  let evidenceKey = null, evidenceType = null;
  const file = form.get("evidence");
  if (file && typeof file === "object" && typeof file.arrayBuffer === "function" && file.size > 0) {
    if (file.size > MAX_BYTES) return json({ success: false, error: "Image must be smaller than 1 MB." }, 400);
    const kind = await sniffImage(file);
    if (!kind) return json({ success: false, error: "Only real JPG, PNG or WebP images are allowed." }, 400);
    evidenceKey = `pending/${crypto.randomUUID()}.${kind.ext}`;
    evidenceType = kind.type;
    await env.DB.prepare(`INSERT INTO evidence (key, content_type, data, created_at) VALUES (?,?,?,?)`)
      .bind(evidenceKey, kind.type, toBase64(await file.arrayBuffer()), new Date().toISOString()).run();
  }

  const now = new Date().toISOString();
  for (let i = 0; i < 6; i++) {
    const caseId = generateCaseId();
    try {
      await env.DB.prepare(`
        INSERT INTO reports (case_id,title,category,platform,identifier,description,risk,status,evidence_key,evidence_type,ip_hash,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,'pending',?,?,?,?,?)`)
        .bind(caseId, title, category, platform, identifier, description, risk, evidenceKey, evidenceType, ipHash, now, now)
        .run();
      return json({ success: true, message: "Report submitted for moderation.", case_id: caseId, status: "pending" }, 201);
    } catch (e) {
      console.error("insert failed", e);
    }
  }
  if (evidenceKey) await env.DB.prepare(`DELETE FROM evidence WHERE key = ?`).bind(evidenceKey).run();
  return json({ success: false, error: "Could not create case. Please try again." }, 500);
}

async function serveEvidence(env, name) {
  if (!name || name.includes("/") || name.includes("..")) return new Response("Not Found", { status: 404 });
  const row = await env.DB.prepare(`SELECT content_type, data FROM evidence WHERE key = ?`).bind("public/" + name).first();
  if (!row) return new Response("Not Found", { status: 404 });
  return new Response(fromBase64(row.data), {
    headers: {
      "Content-Type": row.content_type,
      "Cache-Control": "public, max-age=3600",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": "default-src 'none'",
    },
  });
}

/* ---------------- ADMIN ---------------- */

const unauthorized = () => json({ success: false, error: "Unauthorized" }, 401);

async function adminList(request, env) {
  const status = clean(new URL(request.url).searchParams.get("status"), 30);
  let sql = `SELECT id,case_id,title,category,platform,identifier,description,risk,status,evidence_key,created_at,updated_at FROM reports`;
  const params = [];
  if (STATUSES.includes(status)) { sql += ` WHERE status = ?`; params.push(status); }
  sql += ` ORDER BY created_at DESC LIMIT 200`;
  const { results } = await env.DB.prepare(sql).bind(...params).all();
  return json({ success: true, reports: results });
}

async function adminEvidence(request, env) {
  const key = new URL(request.url).searchParams.get("key") || "";
  if (!/^(pending|public)\/[A-Za-z0-9._-]+$/.test(key)) return new Response("Bad key", { status: 400 });
  const row = await env.DB.prepare(`SELECT content_type, data FROM evidence WHERE key = ?`).bind(key).first();
  if (!row) return new Response("Not Found", { status: 404 });
  return new Response(fromBase64(row.data), {
    headers: { "Content-Type": row.content_type, "Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff" },
  });
}

// Public images live under public/, unpublished ones under pending/
async function moveEvidence(env, report, toPublic) {
  const key = report.evidence_key;
  if (!key) return key;
  const prefix = toPublic ? "public/" : "pending/";
  if (key.startsWith(prefix)) return key;
  const ext = key.split(".").pop();
  const newKey = toPublic ? `public/${report.case_id}.${ext}` : `pending/${crypto.randomUUID()}.${ext}`;
  await env.DB.prepare(`UPDATE evidence SET key = ? WHERE key = ?`).bind(newKey, key).run();
  return newKey;
}

async function adminModerate(request, env, caseId) {
  let body;
  try { body = await request.json(); } catch { return json({ success: false, error: "Invalid JSON." }, 400); }

  const report = await env.DB.prepare(`SELECT * FROM reports WHERE case_id = ?`).bind(caseId).first();
  if (!report) return json({ success: false, error: "Case not found." }, 404);

  const status = body.status === undefined ? report.status : clean(body.status, 30);
  if (!STATUSES.includes(status)) return json({ success: false, error: "Invalid status." }, 400);

  const identifier = typeof body.identifier === "string" ? clean(body.identifier, 200) : report.identifier;

  const makePublic = status === "approved" || status === "corroborated";
  const evidenceKey = await moveEvidence(env, report, makePublic);

  await env.DB.prepare(`UPDATE reports SET status = ?, identifier = ?, evidence_key = ?, updated_at = ? WHERE case_id = ?`)
    .bind(status, identifier, evidenceKey, new Date().toISOString(), caseId).run();

  return json({ success: true, case_id: caseId, status });
}

async function adminDelete(env, caseId) {
  const report = await env.DB.prepare(`SELECT evidence_key FROM reports WHERE case_id = ?`).bind(caseId).first();
  if (!report) return json({ success: false, error: "Case not found." }, 404);
  if (report.evidence_key) await env.DB.prepare(`DELETE FROM evidence WHERE key = ?`).bind(report.evidence_key).run();
  await env.DB.prepare(`DELETE FROM reports WHERE case_id = ?`).bind(caseId).run();
  return json({ success: true, case_id: caseId, deleted: true });
}

/* ---------------- ROUTER ---------------- */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    try {
      if (method === "GET" && pathname === "/api/reports") return listPublic(request, env);
      if (method === "GET" && pathname === "/api/stats") return stats(env);
      if (method === "POST" && pathname === "/api/reports") return createReport(request, env);

      if (method === "GET" && pathname.startsWith("/evidence/"))
        return serveEvidence(env, decodeURIComponent(pathname.slice("/evidence/".length)));

      if (pathname.startsWith("/api/admin/")) {
        if (!(await isAdmin(request, env))) return unauthorized();

        if (method === "GET" && pathname === "/api/admin/reports") return adminList(request, env);
        if (method === "GET" && pathname === "/api/admin/evidence") return adminEvidence(request, env);

        const m = pathname.match(/^\/api\/admin\/reports\/([^/]+)$/);
        if (m) {
          const caseId = decodeURIComponent(m[1]);
          if (method === "PATCH") return adminModerate(request, env, caseId);
          if (method === "DELETE") return adminDelete(env, caseId);
        }
      }

      if (pathname.startsWith("/api/")) return json({ success: false, error: "Not found." }, 404);
      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error(error);
      return json({ success: false, error: "Internal server error." }, 500);
    }
  },
};
