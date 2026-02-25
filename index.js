import "dotenv/config";
import express from "express";
import fetch from "node-fetch";
import rateLimit from "express-rate-limit";

const app = express();

// Si tu es derrière un reverse proxy (Render/Railway/Nginx), active ceci
// pour que le rate limit utilise la vraie IP client.
app.set("trust proxy", 1);

app.use(express.json({ limit: "1mb" }));

// CORS minimal (utile en dev navigateur)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  // Ajout de x-api-key pour l’auth côté app
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Api-Key");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Rate limiting (anti-abus)
app.use(
  rateLimit({
    windowMs: 60_000, // 1 min
    max: Number(process.env.RATE_LIMIT_MAX ?? 60), // 60 req/min/IP par défaut
    standardHeaders: true,
    legacyHeaders: false,
  })
);

const ENV = process.env.PISTE_ENV ?? "sandbox";
const CLIENT_ID = process.env.PISTE_CLIENT_ID ?? process.env.LEGIFRANCE_CLIENT_ID;
const CLIENT_SECRET = process.env.PISTE_CLIENT_SECRET ?? process.env.LEGIFRANCE_CLIENT_SECRET;

// API keys "internes" pour tes collègues (recommandé en prod)
// Exemple : APP_API_KEYS=cle1,cle2,cle3
const API_KEYS = String(process.env.APP_API_KEYS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function requireApiKey(req, res, next) {
  // Si aucune clé n’est définie, on n’exige rien (pratique en dev local)
  if (API_KEYS.length === 0) return next();

  const k = req.header("x-api-key") || req.header("X-Api-Key");
  if (!k || !API_KEYS.includes(k)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ✅ Route de diagnostic (ne révèle pas les secrets)
app.get("/health", (req, res) => {
  res.json({
    env: ENV,
    tokenUrl:
      ENV === "production"
        ? "https://oauth.piste.gouv.fr/api/oauth/token"
        : "https://sandbox-oauth.piste.gouv.fr/api/oauth/token",
    apiBase:
      ENV === "production"
        ? "https://api.piste.gouv.fr/dila/legifrance/lf-engine-app"
        : "https://sandbox-api.piste.gouv.fr/dila/legifrance/lf-engine-app",
    hasClientId: Boolean(CLIENT_ID),
    hasClientSecret: Boolean(CLIENT_SECRET),
    clientIdLen: CLIENT_ID ? String(CLIENT_ID).trim().length : 0,
    clientSecretLen: CLIENT_SECRET ? String(CLIENT_SECRET).trim().length : 0,
    apiKeysConfigured: API_KEYS.length,
  });
});

if (!CLIENT_ID || !CLIENT_SECRET) {
  throw new Error("Missing PISTE_CLIENT_ID / PISTE_CLIENT_SECRET env vars");
}

const TOKEN_URL =
  ENV === "production"
    ? "https://oauth.piste.gouv.fr/api/oauth/token"
    : "https://sandbox-oauth.piste.gouv.fr/api/oauth/token";

const API_BASE =
  ENV === "production"
    ? "https://api.piste.gouv.fr/dila/legifrance/lf-engine-app"
    : "https://sandbox-api.piste.gouv.fr/dila/legifrance/lf-engine-app";

// Cache token OAuth (évite de redemander un token à chaque appel)
let cachedToken = null;
let tokenExpiresAt = 0;

async function getToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAt - 10_000) {
    return cachedToken;
  }

  const id = String(CLIENT_ID).trim();
  const secret = String(CLIENT_SECRET).trim();

  // OAuth Client Credentials via HTTP Basic (plus compatible)
  const basic = Buffer.from(`${id}:${secret}`).toString("base64");

  const r = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams({ grant_type: "client_credentials" }).toString(),
  });

  if (!r.ok) throw new Error(`Token HTTP ${r.status}: ${await r.text()}`);
  const j = await r.json();

  cachedToken = j.access_token;
  const expiresInMs = (Number(j.expires_in) || 60) * 1000;
  tokenExpiresAt = Date.now() + expiresInMs;

  return cachedToken;
}

function extractLegifranceId(rawUrl) {
  const s = String(rawUrl || "").trim();

  // IDs en clair dans l’URL
  let m = s.match(
    /\b(JORFTEXT\d{12}|LEGITEXT\d{12}|LEGIARTI\d{12}|JORFARTI\d{12}|JORFCONT\d{12}|LEGISCTA\d{12}|KALITEXT\d{12}|KALIARTI\d{12})\b/
  );
  if (m) return m[1];

  // IDs dans query params (cidTexte, idArticle, etc.)
  try {
    const u = new URL(s);
    const candidates = [
      u.searchParams.get("idArticle"),
      u.searchParams.get("articleId"),
      u.searchParams.get("cidTexte"),
      u.searchParams.get("textCid"),
      u.searchParams.get("id"),
    ].filter(Boolean);

    for (const c of candidates) {
      m = String(c).match(
        /\b(JORFTEXT\d{12}|LEGITEXT\d{12}|LEGIARTI\d{12}|JORFARTI\d{12}|JORFCONT\d{12}|LEGISCTA\d{12}|KALITEXT\d{12}|KALIARTI\d{12})\b/
      );
      if (m) return m[1];
    }
  } catch {}

  return null;
}

app.post("/legifrance/import", requireApiKey, async (req, res) => {
  try {
    const url = String(req.body?.url ?? "");
    const id = extractLegifranceId(url);
    if (!id) return res.status(400).json({ error: "URL does not contain a known Legifrance ID" });

    const token = await getToken();

    let endpoint;
    let payload;

    if (id.startsWith("JORFTEXT")) {
      endpoint = "/consult/jorf";
      payload = { textCid: id };
    } else if (id.startsWith("LEGITEXT")) {
      endpoint = "/consult/legiPart";
      payload = { date: Date.now(), textId: id };
    } else if (id.startsWith("KALIARTI")) {
      endpoint = "/consult/kaliArticle";
      payload = { id };
    } else if (id.startsWith("KALITEXT")) {
      endpoint = "/consult/kaliText";
      payload = { id };
    } else {
      endpoint = "/consult/getArticle";
      payload = { id };
    }

    const r = await fetch(API_BASE + endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!r.ok) throw new Error(`Consult HTTP ${r.status}: ${await r.text()}`);
    const data = await r.json();

    res.json({ id, data });
  } catch (e) {
    res.status(500).json({ error: String(e?.message ?? e) });
  }
});

const PORT = process.env.PORT || 8787; // 8787 en local, PORT en prod
app.listen(PORT, () => {
  console.log(`Legifrance proxy running on :${PORT} (env=${ENV})`);
  console.log(
    `[sanity] hasClientId=${Boolean(CLIENT_ID)} hasClientSecret=${Boolean(CLIENT_SECRET)} ` +
      `clientIdLen=${CLIENT_ID ? String(CLIENT_ID).trim().length : 0} ` +
      `clientSecretLen=${CLIENT_SECRET ? String(CLIENT_SECRET).trim().length : 0}`
  );
});