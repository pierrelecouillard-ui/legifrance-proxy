import "dotenv/config";
import express from "express";
import fetch from "node-fetch";
import rateLimit from "express-rate-limit";

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  // logs légers (utile sur Render)
  if (req.path.startsWith("/legifrance/")) {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  }
  next();
});


// CORS minimal
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Api-Key");
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
const CLIENT_SECRET = process.env.PISTE_CLIENT_SECRET ?? process.env.LEGIFRANCE_CLIENT_SECRET;

const API_KEYS = String(process.env.APP_API_KEYS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function requireApiKey(req, res, next) {
  if (API_KEYS.length === 0) return next();
  const k = req.header("x-api-key") || req.header("X-Api-Key");
  if (!k || !API_KEYS.includes(k)) return res.status(401).json({ error: "Unauthorized" });
  next();
}

app.get("/health", (req, res) => {
  res.json({
    env: ENV,
    apiBase:
      ENV === "production"
        ? "https://api.piste.gouv.fr/dila/legifrance/lf-engine-app"
        : "https://sandbox-api.piste.gouv.fr/dila/legifrance/lf-engine-app",
    tokenUrl:
      ENV === "production"
        ? "https://oauth.piste.gouv.fr/api/oauth/token"
        : "https://sandbox-oauth.piste.gouv.fr/api/oauth/token",
    hasClientId: Boolean(CLIENT_ID),
    hasClientSecret: Boolean(CLIENT_SECRET),
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

let cachedToken = null;
let tokenExpiresAt = 0;

async function getToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAt - 10_000) return cachedToken;

  const id = String(CLIENT_ID).trim();
  const secret = String(CLIENT_SECRET).trim();
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
  tokenExpiresAt = Date.now() + (Number(j.expires_in) || 60) * 1000;
  return cachedToken;
}

function extractLegifranceId(raw) {
  const s = String(raw || "").trim();
  let m = s.match(
    /\b(JORFTEXT\d{12}|LEGITEXT\d{12}|LEGIARTI\d{12}|JORFARTI\d{12}|JORFCONT\d{12}|JORFSCTA\d{12}|LEGISCTA\d{12}|KALITEXT\d{12}|KALIARTI\d{12})\b/
  );
  if (m) return m[1];
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
        /\b(JORFTEXT\d{12}|LEGITEXT\d{12}|LEGIARTI\d{12}|JORFARTI\d{12}|JORFCONT\d{12}|JORFSCTA\d{12}|LEGISCTA\d{12}|KALITEXT\d{12}|KALIARTI\d{12})\b/
      );
      if (m) return m[1];
    }
  } catch {}
  return null;
}

async function postJson(endpoint, payload) {
  const token = await getToken();
  const r = await fetch(API_BASE + endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
  });

  const text = await r.text();
  if (!r.ok) {
    // renvoie un message exploitable côté front
    throw new Error(`PISTE ${endpoint} HTTP ${r.status}: ${text.slice(0, 800)}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    // si jamais l'API renvoie autre chose
    return { raw: text };
  }
}

async function consultById(id) {
  // Choix endpoint/payload par type d'ID
  if (id.startsWith("JORFTEXT")) {
    // Certaines configs attendent {id}, d'autres {textCid}; on tente les 2.
    try {
      return await postJson("/consult/jorf", { id });
    } catch (e) {
      return await postJson("/consult/jorf", { textCid: id });
    }
  }

  if (id.startsWith("LEGITEXT")) {
    // date au format YYYY-MM-DD (attendu par l'API)
    return await postJson("/consult/legiPart", {
      date: new Date().toISOString().slice(0, 10),
      textId: id,
    });
  }

  // Sections (JORF / LEGI)
  if (id.startsWith("JORFSCTA") || id.startsWith("LEGISCTA")) {
    // endpoint section (best-effort)
    return await postJson("/consult/getSection", { id });
  }


  if (id.startsWith("KALIARTI")) return await postJson("/consult/kaliArticle", { id });
  if (id.startsWith("KALITEXT")) return await postJson("/consult/kaliText", { id });

  // articles & autres IDs
  return await postJson("/consult/getArticle", { id });
}


// ✅ NOUVEL endpoint attendu par ton AppCore

// ✅ Consult + annexes (résout les sections "Annexe" d'un JORFTEXT)
app.post("/legifrance/consultDeep", requireApiKey, async (req, res) => {
  try {
    const bodyId = req.body?.id ? String(req.body.id) : null;
    const bodyUrl = req.body?.url ? String(req.body.url) : "";
    const id = bodyId || extractLegifranceId(bodyUrl);
    if (!id) return res.status(400).json({ error: "Missing or invalid Legifrance id/url" });

    const data = await consultById(id);

    // Résolution best-effort des annexes (sections) uniquement pour JORFTEXT
    const annexes = [];
    const secs = Array.isArray(data?.sections) ? data.sections : [];
    for (const s of secs) {
      const sid = s?.id || s?.cid;
      if (typeof sid !== "string") continue;
      if (!/^JORFSCTA\d{12}$/.test(sid)) continue;
      try {
        const sdata = await consultById(sid);
        annexes.push({ id: sid, data: sdata });
      } catch (e) {
        annexes.push({ id: sid, error: String(e?.message ?? e) });
      }
    }

    res.json({ id, data, annexes });
  } catch (e) {
    res.status(500).json({ error: String(e?.message ?? e) });
  }
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

// Compat: garde /legifrance/import mais accepte {id,url}
app.post("/legifrance/import", requireApiKey, async (req, res) => {
  try {
    const bodyId = req.body?.id ? String(req.body.id) : null;
    const bodyUrl = req.body?.url ? String(req.body.url) : "";

    const id = bodyId || extractLegifranceId(bodyUrl);
    if (!id) return res.status(400).json({ error: "URL does not contain a known Legifrance ID" });

    const data = await consultById(id);
    res.json({ id, data });
  } catch (e) {
    res.status(500).json({ error: String(e?.message ?? e) });
  }
});

const PORT = process.env.PORT || 8787;
app.listen(PORT, () => {
  console.log(`Legifrance proxy running on :${PORT} (env=${ENV})`);
});
