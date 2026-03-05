import "dotenv/config";
import express from "express";
import fetch from "node-fetch";
import rateLimit from "express-rate-limit";

/**
 * legifrance-proxy (PISTE)
 *
 * - Évite les 403 Cloudflare (on ne scrape jamais legifrance.gouv.fr)
 * - Appelle l'API PISTE Légifrance (OAuth2)
 * - Expose des endpoints simples pour ton AppCore
 * - /legifrance/consultDeep essaie de récupérer le contenu complet via ELI
 */

const app = express();

app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));

// CORS minimal
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Api-Key"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Rate limiting
app.use(
  rateLimit({
    windowMs: 60_000,
    max: Number(process.env.RATE_LIMIT_MAX ?? 60),
    standardHeaders: true,
    legacyHeaders: false,
  })
);

const ENV = process.env.PISTE_ENV ?? "sandbox";
const CLIENT_ID = process.env.PISTE_CLIENT_ID ?? process.env.LEGIFRANCE_CLIENT_ID;
const CLIENT_SECRET =
  process.env.PISTE_CLIENT_SECRET ?? process.env.LEGIFRANCE_CLIENT_SECRET;

// Exemple : APP_API_KEYS=cle1,cle2
const API_KEYS = String(process.env.APP_API_KEYS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const tokenUrl =
  ENV === "prod"
    ? "https://oauth.piste.gouv.fr/api/oauth/token"
    : "https://sandbox-oauth.piste.gouv.fr/api/oauth/token";

const apiBase =
  ENV === "prod"
    ? "https://api.piste.gouv.fr/dila/legifrance/lf-engine-app"
    : "https://sandbox-api.piste.gouv.fr/dila/legifrance/lf-engine-app";

function requireApiKey(req, res, next) {
  if (!API_KEYS.length) return next();
  const key = req.header("x-api-key") || req.header("X-Api-Key");
  if (!key || !API_KEYS.includes(String(key))) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// -------- OAuth / PISTE helpers --------

let cachedToken = null;
let cachedTokenExpMs = 0;

async function getAccessToken() {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    throw new Error("Missing PISTE_CLIENT_ID / PISTE_CLIENT_SECRET");
  }

  const now = Date.now();
  if (cachedToken && now < cachedTokenExpMs - 10_000) return cachedToken;

  const basic = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64");
  const r = await fetch(tokenUrl, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  const txt = await r.text();
  if (!r.ok) throw new Error(`OAuth token HTTP ${r.status}: ${txt}`);

  const json = JSON.parse(txt);
  cachedToken = json.access_token;
  const expiresInSec = Number(json.expires_in ?? 3600);
  cachedTokenExpMs = now + expiresInSec * 1000;
  return cachedToken;
}

async function pistePost(path, bodyObj) {
  const token = await getAccessToken();
  const url = `${apiBase}${path}`;

  const r = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(bodyObj ?? {}),
  });

  const txt = await r.text();
  if (!r.ok) {
    const err = new Error(`PISTE ${path} HTTP ${r.status}: ${txt}`);
    err.status = r.status;
    err.body = txt;
    throw err;
  }

  return txt ? JSON.parse(txt) : null;
}

// -------- Utils --------

function extractLegifranceId(input) {
  const s = String(input ?? "").trim();
  if (!s) return null;

  // direct id
  const direct = s.match(/^(JORFTEXT|LEGITEXT|LEGIARTI|JORFARTI)\d+/i);
  if (direct) return direct[0].toUpperCase();

  // from URL
  const m = s.match(/\b(JORFTEXT|LEGITEXT|LEGIARTI|JORFARTI)\d+\b/i);
  return m ? m[0].toUpperCase() : null;
}

async function consultById(id) {
  return pistePost("/consult", { id: String(id) });
}

async function consultFullByEli(eliPath) {
  const eli = String(eliPath ?? "").trim();
  if (!eli) return null;
  return pistePost("/consult/eliAndAliasRedirectionTexte", { idEliOrAlias: eli });
}

function extractAnnexesFromFull(full) {
  const annexes = [];
  const sections = Array.isArray(full?.sections) ? full.sections : [];

  for (const s of sections) {
    const title = String(s?.title ?? "");
    if (!/annexe/i.test(title)) continue;
    annexes.push({
      id: s?.id ?? s?.cid ?? null,
      title: title || "Annexe",
      articles: Array.isArray(s?.articles) ? s.articles : [],
      raw: s,
    });
  }

  return annexes;
}

// -------- Routes --------

app.get("/health", (req, res) => {
  res.json({
    env: ENV,
    tokenUrl,
    apiBase,
    hasClientId: Boolean(CLIENT_ID),
    hasClientSecret: Boolean(CLIENT_SECRET),
    clientIdLen: CLIENT_ID ? String(CLIENT_ID).length : 0,
    clientSecretLen: CLIENT_SECRET ? String(CLIENT_SECRET).length : 0,
    apiKeysConfigured: API_KEYS.length,
  });
});

app.post("/legifrance/consult", requireApiKey, async (req, res) => {
  try {
    const bodyId = req.body?.id ? String(req.body.id) : null;
    const bodyUrl = req.body?.url ? String(req.body.url) : "";

    const id = bodyId || extractLegifranceId(bodyUrl);
    if (!id) return res.status(400).json({ error: "Missing or invalid Legifrance id/url" });

    const data = await consultById(id);
    res.json({ id, data });
  } catch (e) {
    res.status(500).json({ error: String(e?.message ?? e) });
  }
});

// Compat avec ton AppCore (ancienne route)
app.post("/legifrance/import", requireApiKey, async (req, res) => {
  try {
    const bodyId = req.body?.id ? String(req.body.id) : null;
    const bodyUrl = req.body?.url ? String(req.body.url) : "";

    const id = bodyId || extractLegifranceId(bodyUrl);
    if (!id) return res.status(400).json({ error: "Missing or invalid Legifrance id/url" });

    const data = await consultById(id);
    res.json({ id, data });
  } catch (e) {
    res.status(500).json({ error: String(e?.message ?? e) });
  }
});

/**
 * Deep import:
 * - consult classique (data)
 * - + consult "full" via ELI (full)
 * - + annexes extraites depuis full (si dispo)
 */
app.post("/legifrance/consultDeep", requireApiKey, async (req, res) => {
  try {
    const bodyId = req.body?.id ? String(req.body.id) : null;
    const bodyUrl = req.body?.url ? String(req.body.url) : "";

    const id = bodyId || extractLegifranceId(bodyUrl);
    if (!id) return res.status(400).json({ error: "Missing or invalid Legifrance id/url" });

    const data = await consultById(id);

    let full = null;
    let annexes = [];
    if (data?.eli) {
      full = await consultFullByEli(data.eli);
      annexes = extractAnnexesFromFull(full);
    }

    res.json({ id, data, full, annexes });
  } catch (e) {
    res.status(500).json({ error: String(e?.message ?? e) });
  }
});

const port = Number(process.env.PORT ?? 8787);
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`legifrance-proxy listening on :${port} (ENV=${ENV})`);
});
