import "dotenv/config";
import express from "express";
import fetch from "node-fetch";
import rateLimit from "express-rate-limit";

const app = express();

// Si tu es derrière un reverse proxy (Render/Railway/Nginx), active ceci
// pour que le rate limit utilise la vraie IP client.
app.set("trust proxy", 1);

app.use(express.json({ limit: "2mb" }));

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

// API keys "internes" (recommandé en prod)
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
  if (cachedToken && now < tokenExpiresAt - 10_000) return cachedToken;

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
    /\b(JORFTEXT\d{12}|LEGITEXT\d{12}|LEGIARTI\d{12}|JORFARTI\d{12}|JORFCONT\d{12}|LEGISCTA\d{12}|JORFSCTA\d{12}|KALITEXT\d{12}|KALIARTI\d{12})\b/
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
        /\b(JORFTEXT\d{12}|LEGITEXT\d{12}|LEGIARTI\d{12}|JORFARTI\d{12}|JORFCONT\d{12}|LEGISCTA\d{12}|JORFSCTA\d{12}|KALITEXT\d{12}|KALIARTI\d{12})\b/
      );
      if (m) return m[1];
    }
  } catch {}

  return null;
}

async function pistePost(endpoint, payload) {
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

  if (!r.ok) {
    const t = await r.text();
    throw new Error(`PISTE ${endpoint} HTTP ${r.status}: ${t}`);
  }
  return r.json();
}

async function consultById(id) {
  // Important:
  // - /consult/jorf attend { textCid }
  // - /consult/legiPart attend { textId, date }
  // - /consult/getArticle attend { id } pour les articles isolés
  if (id.startsWith("JORFTEXT")) {
    return pistePost("/consult/jorf", { textCid: id });
  }
  if (id.startsWith("LEGITEXT")) {
    return pistePost("/consult/legiPart", { date: Date.now(), textId: id });
  }
  if (id.startsWith("KALIARTI")) {
    return pistePost("/consult/kaliArticle", { id });
  }
  if (id.startsWith("KALITEXT")) {
    return pistePost("/consult/kaliText", { id });
  }
  // articles / sections divers
  return pistePost("/consult/getArticle", { id });
}


// ✅ Recherche via PISTE (évite Cloudflare)
// Body attendu (simple):
// { query: "cap carreleur mosaïste", fond?: "JORF"|"LODA_DATE"|"ALL", pageSize?: 25, pageNumber?: 1 }
//
// Le proxy construit une requête "search" de l'API Légifrance (lf-engine-app/search)
// en ciblant principalement le TITLE, et en filtrant par NATURE=ARRETE par défaut.
app.post("/legifrance/search", requireApiKey, async (req, res) => {
  try {
    const query = String(req.body?.query || req.body?.q || "").trim();
    if (!query) return res.status(400).json({ error: "Missing query" });

    const fond = String(req.body?.fond || "JORF").trim(); // ex: JORF, LODA_DATE, ALL
    const pageSize = Math.min(Number(req.body?.pageSize ?? 25) || 25, 100);
    const pageNumber = Math.max(Number(req.body?.pageNumber ?? 1) || 1, 1);

    const payload = {
      fond,
      recherche: {
        champs: [
          {
            typeChamp: "TITLE",
            operateur: "ET",
            criteres: [
              {
                typeRecherche: "UN_DES_MOTS",
                valeur: query,
                operateur: "ET",
              },
            ],
          },
        ],
        // Par défaut, on vise les textes "arrêté" (souvent le cas pour les diplômes)
        filtres: Array.isArray(req.body?.filtres)
          ? req.body.filtres
          : [
              {
                facette: "NATURE",
                valeurs: ["ARRETE"],
              },
            ],
        operateur: "ET",
        pageNumber,
        pageSize,
        sort: String(req.body?.sort || "SIGNATURE_DATE_DESC"),
        typePagination: String(req.body?.typePagination || "DEFAUT"),
      },
    };

    const data = await pistePost("/search", payload);
    res.json({ query, fond, data });
  } catch (e) {
    res.status(500).json({ error: String(e?.message ?? e) });
  }
});

// ✅ NOUVEL endpoint attendu par ton AppCore
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
    if (!id) return res.status(400).json({ error: "Missing or invalid Legifrance id/url" });

    const data = await consultById(id);
    res.json({ id, data });
  } catch (e) {
    res.status(500).json({ error: String(e?.message ?? e) });
  }
});

/**
 * ✅ consultDeep:
 * - récupère le texte (consultById)
 * - tente de récupérer le contenu des annexes (sections "Annexe") via
 *   POST /chrono/textCidAndElementCid
 *
 * Pourquoi: l'ancien appel "getSection" donne parfois 403, alors que cet endpoint
 * est documenté et (souvent) autorisé.
 */
app.post("/legifrance/consultDeep", requireApiKey, async (req, res) => {
  try {
    const bodyId = req.body?.id ? String(req.body.id) : null;
    const bodyUrl = req.body?.url ? String(req.body.url) : "";

    const id = bodyId || extractLegifranceId(bodyUrl);
    if (!id) return res.status(400).json({ error: "Missing or invalid Legifrance id/url" });

    const data = await consultById(id);

    // Detect annex-like sections (JORF renvoie souvent "Annexe")
    const sections = Array.isArray(data?.sections) ? data.sections : [];
    const annexSections = sections.filter((s) => String(s?.title ?? "").toLowerCase().includes("annexe"));

    const annexes = [];
    for (const s of annexSections) {
      const sectionCid = String(s?.cid ?? s?.id ?? "");
      const title = String(s?.title ?? "Annexe");

      if (!sectionCid) {
        annexes.push({ id: null, title, error: "Missing section cid" });
        continue;
      }

      try {
        // Endpoint OpenAPI: post/chrono/textCidAndElementCid
        const excerpt = await pistePost("/chrono/textCidAndElementCid", {
          textCid: id,
          elementCid: sectionCid,
        });

        annexes.push({ id: sectionCid, title, excerpt });
      } catch (err) {
        annexes.push({ id: sectionCid, title, error: String(err?.message ?? err) });
      }
    }

    res.json({ id, data, annexes });
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
