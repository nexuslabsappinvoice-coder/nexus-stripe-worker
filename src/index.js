/**
 * ============================================================
 * NEXUS STRIPE OAUTH — Cloudflare Worker v3.2.0
 * ============================================================
 * Soporta AMBOS modos TEST y LIVE dinámicamente según el parámetro
 * `mode` que envía la app en cada request.
 *
 * ─── VARIABLES DE ENTORNO REQUERIDAS EN CLOUDFLARE ──────────
 *   STRIPE_TEST_CLIENT_ID     → ca_...      (Stripe Connect, TEST)
 *   STRIPE_TEST_SECRET_KEY    → sk_test_... (API keys, TEST)
 *   STRIPE_LIVE_CLIENT_ID     → ca_...      (Stripe Connect, LIVE)
 *   STRIPE_LIVE_SECRET_KEY    → sk_live_... (API keys, LIVE)
 *   APP_SCHEME                → nexusbillings
 *
 * ─── KV NAMESPACE REQUERIDO (para /trial/check) ─────────────
 *   Variable name: TRIAL_KV
 *   Crea un KV namespace nuevo llamado "nexus-trial-kv" y
 *   bindealo en Settings → Variables → KV Namespace Bindings.
 *
 * ─── REDIRECT URIs EN STRIPE ────────────────────────────────
 * Agrega AMBOS (en test y live settings):
 *   https://nexus-stripe-oauth.nexuslabsappinvoice.workers.dev/oauth/callback
 * ============================================================
 */

const VERSION = "3.2.0";
const ENDPOINTS = ["/connect-url", "/oauth/callback", "/account/status", "/account/deauthorize", "/checkout", "/checkout/status", "/trial/check"];

// Elige el par (clientId, secretKey) correcto según el modo pedido.
function keysFor(env, mode) {
  const isLive = mode === "live";
  const clientId = isLive ? env.STRIPE_LIVE_CLIENT_ID : env.STRIPE_TEST_CLIENT_ID;
  const secretKey = isLive ? env.STRIPE_LIVE_SECRET_KEY : env.STRIPE_TEST_SECRET_KEY;
  return { clientId, secretKey, mode: isLive ? "live" : "test" };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    try {
      if (path === "/" || path === "") {
        return withCors(json({ service: "nexus-stripe-oauth", version: VERSION, endpoints: ENDPOINTS }));
      }

      // ───────── POST /connect-url ─────────
      if (path === "/connect-url" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const device_id = body.device_id || "unknown";
        const { clientId, mode } = keysFor(env, body.mode);
        if (!clientId) return withCors(json({ error: "client_id_not_configured", mode }, 500));

        const state = btoa(JSON.stringify({ device_id, mode, ts: Date.now() }));
        const redirectUri = `${url.origin}/oauth/callback`;
        const authUrl = "https://connect.stripe.com/oauth/authorize?" + new URLSearchParams({
          response_type: "code",
          client_id: clientId,
          scope: "read_write",
          redirect_uri: redirectUri,
          state,
        }).toString();
        return withCors(json({ url: authUrl, redirect_uri: redirectUri, mode }));
      }

      // ───────── GET /oauth/callback ─────────
      if (path === "/oauth/callback" && request.method === "GET") {
        const code = url.searchParams.get("code");
        const stateRaw = url.searchParams.get("state");
        const err = url.searchParams.get("error");
        const errDesc = url.searchParams.get("error_description");

        if (err) return htmlError(`Stripe rechazó la conexión: ${err}`, errDesc || "");
        if (!code) return htmlError("Falta el código de autorización", "");

        let stateData = { device_id: "unknown", mode: "test" };
        try { if (stateRaw) stateData = JSON.parse(atob(stateRaw)); } catch { /* ignore */ }

        const { secretKey, mode } = keysFor(env, stateData.mode);
        if (!secretKey) return htmlError("Secret key no configurada en el Worker", mode);

        const tokenRes = await fetch("https://connect.stripe.com/oauth/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_secret: secretKey,
            code,
            grant_type: "authorization_code",
          }).toString(),
        });
        const tokenData = await tokenRes.json();
        if (tokenData.error) {
          return htmlError(`Stripe OAuth error: ${tokenData.error}`, tokenData.error_description || "");
        }
        const stripeUserId = tokenData.stripe_user_id;
        if (!stripeUserId) return htmlError("Stripe no devolvió stripe_user_id", JSON.stringify(tokenData));

        const scheme = env.APP_SCHEME || "nexusbillings";
        const deepLink = `${scheme}://stripe-return?status=success` +
          `&stripe_user_id=${encodeURIComponent(stripeUserId)}` +
          `&device_id=${encodeURIComponent(stateData.device_id)}` +
          `&mode=${encodeURIComponent(mode)}`;

        return successHtml(deepLink, mode);
      }

      // ───────── POST /account/status ─────────
      if (path === "/account/status" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const account_id = body.account_id;
        if (!account_id || !account_id.startsWith("acct_")) {
          return withCors(json({ error: "invalid_account_id" }, 400));
        }
        const { secretKey, mode } = keysFor(env, body.mode);
        if (!secretKey) return withCors(json({ error: "secret_key_not_configured", mode }, 500));

        const res = await fetch(`https://api.stripe.com/v1/accounts/${account_id}`, {
          headers: { "Authorization": `Bearer ${secretKey}` },
        });
        const data = await res.json();
        if (data.error) {
          return withCors(json({
            error: data.error.code || "stripe_error",
            detail: data.error.message,
            code: data.error.code,
            mode,
          }, res.status));
        }
        return withCors(json({
          connected: true,
          account_id: data.id,
          business_name: data.business_profile?.name || data.settings?.dashboard?.display_name || null,
          country: data.country,
          default_currency: data.default_currency,
          charges_enabled: !!data.charges_enabled,
          payouts_enabled: !!data.payouts_enabled,
          livemode: !!data.livemode,
        }));
      }

      // ───────── POST /account/deauthorize ─────────
      if (path === "/account/deauthorize" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const account_id = body.account_id;
        if (!account_id) return withCors(json({ error: "invalid_account_id" }, 400));

        const { clientId, secretKey, mode } = keysFor(env, body.mode);
        const res = await fetch("https://connect.stripe.com/oauth/deauthorize", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${secretKey}`,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            client_id: clientId,
            stripe_user_id: account_id,
          }).toString(),
        });
        const data = await res.json();
        return withCors(json({
          ok: !data.error,
          stripe_user_id: account_id,
          mode,
          detail: data.error?.message,
        }, data.error ? res.status : 200));
      }

      // ───────── POST /checkout ─────────
      if (path === "/checkout" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const account_id = body.account_id;
        const amount = Number(body.amount);
        const currency = (body.currency || "usd").toLowerCase();
        const description = body.description || "Invoice payment";
        const customer_email = body.customer_email;
        const metadata = body.metadata || {};

        if (!account_id || !account_id.startsWith("acct_")) {
          return withCors(json({ error: "invalid_account_id" }, 400));
        }
        if (!amount || amount <= 0) {
          return withCors(json({ error: "invalid_amount" }, 400));
        }
        const { secretKey, mode } = keysFor(env, body.mode);
        if (!secretKey) return withCors(json({ error: "secret_key_not_configured", mode }, 500));

        const amountCents = Math.round(amount * 100);
        // iter-110 · Platform commission — Nexus Labs se lleva 0.5% de
        // cada transacción de sus users conectados.  Stripe descuenta
        // esto ANTES de transferir al connected account.  Ajustable
        // vía body.application_fee_percent (0-10) para pruebas.
        const feePercentRaw = Number(body.application_fee_percent);
        const feePercent = Number.isFinite(feePercentRaw) && feePercentRaw >= 0 && feePercentRaw <= 10
          ? feePercentRaw
          : 0.5;   // default 0.5%
        const applicationFeeCents = Math.round(amountCents * feePercent / 100);
        const params = new URLSearchParams({
          "mode": "payment",
          "line_items[0][price_data][currency]": currency,
          "line_items[0][price_data][product_data][name]": description.slice(0, 250),
          "line_items[0][price_data][unit_amount]": String(amountCents),
          "line_items[0][quantity]": "1",
          "success_url": "https://nexuslabsappinvoice-coder.github.io/Legal/payment-success.html?session_id={CHECKOUT_SESSION_ID}",
          "cancel_url": "https://nexuslabsappinvoice-coder.github.io/Legal/payment-cancelled.html?session_id={CHECKOUT_SESSION_ID}",
        });
        if (applicationFeeCents > 0) {
          params.set("payment_intent_data[application_fee_amount]", String(applicationFeeCents));
        }
        if (customer_email) params.set("customer_email", customer_email);
        for (const [k, v] of Object.entries(metadata)) {
          params.append(`metadata[${k}]`, String(v));
        }

        const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${secretKey}`,
            "Content-Type": "application/x-www-form-urlencoded",
            "Stripe-Account": account_id,
          },
          body: params.toString(),
        });
        const data = await res.json();
        if (data.error) {
          return withCors(json({
            error: "checkout_failed",
            code: data.error.code || "stripe_error",
            detail: data.error.message,
            mode,
          }, res.status));
        }
        return withCors(json({
          url: data.url,
          session_id: data.id,
          expires_at: data.expires_at,
          mode,
        }));
      }

      // ───────── POST /checkout/status ─────────
      // iter-108 · Auto-verify pagos.  Consulta el estado de una
      // Checkout Session usando el header Stripe-Account de la cuenta
      // conectada.  Devuelve { paid: bool, amount_total, currency,
      // payment_intent, session_id }.
      if (path === "/checkout/status" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const session_id = body.session_id;
        const account_id = body.account_id;
        if (!session_id || !session_id.startsWith("cs_")) {
          return withCors(json({ error: "invalid_session_id" }, 400));
        }
        if (!account_id || !account_id.startsWith("acct_")) {
          return withCors(json({ error: "invalid_account_id" }, 400));
        }
        const { secretKey, mode } = keysFor(env, body.mode);
        if (!secretKey) return withCors(json({ error: "secret_key_not_configured", mode }, 500));

        const res = await fetch(`https://api.stripe.com/v1/checkout/sessions/${session_id}`, {
          headers: {
            "Authorization": `Bearer ${secretKey}`,
            "Stripe-Account": account_id,
          },
        });
        const data = await res.json();
        if (data.error) {
          return withCors(json({
            error: "status_lookup_failed",
            code: data.error.code || "stripe_error",
            detail: data.error.message,
            mode,
          }, res.status));
        }
        return withCors(json({
          session_id: data.id,
          paid: data.payment_status === "paid",
          payment_status: data.payment_status,
          amount_total: data.amount_total,
          currency: data.currency,
          payment_intent: data.payment_intent,
          customer_email: data.customer_details?.email || null,
          mode,
        }));
      }

      // ───────── POST /trial/check ─────────
      // iter-111 · Anti-reset del trial premium.  El usuario envía un
      // device_id derivado de Application.getAndroidId() (Android) o
      // Application.getIosIdForVendorAsync() (iOS).  El Worker guarda
      // en KV la fecha del PRIMER contacto de ese device.  Aunque el
      // usuario desinstale/reinstale la app, el device_id se mantiene
      // en el hardware, así que devolvemos la fecha ORIGINAL del
      // trial y la app la usa en vez de crear una nueva.
      //
      // Config Cloudflare requerida:
      //   Settings → Variables → KV Namespace Bindings:
      //   Variable name: TRIAL_KV
      //   KV namespace : (crea uno nuevo llamado "nexus-trial-kv")
      if (path === "/trial/check" && request.method === "POST") {
        const body = await request.json().catch(() => ({}));
        const device_id = String(body.device_id || "").trim();
        const app_id = String(body.app_id || "nexus-billings").trim();
        if (!device_id || device_id.length < 4) {
          return withCors(json({ error: "invalid_device_id" }, 400));
        }
        if (!env.TRIAL_KV) {
          // Si el KV no está configurado, devolvemos degradado gracefully:
          // la app usará la fecha local sin protección remota.
          return withCors(json({
            error: "kv_not_configured",
            hint: "Añade un KV namespace 'TRIAL_KV' en Cloudflare Settings → Variables → KV Namespace Bindings",
            first_seen_at: null,
            is_new: true,
          }, 200));
        }
        const key = `trial:${app_id}:${device_id}`;
        const existing = await env.TRIAL_KV.get(key);
        const now = new Date().toISOString();
        if (existing) {
          const daysSince = Math.floor((Date.now() - new Date(existing).getTime()) / 86400000);
          return withCors(json({
            first_seen_at: existing,
            days_since_first: daysSince,
            is_new: false,
          }));
        }
        // Primer contacto — registramos.  TTL de 5 años (más que
        // suficiente para un trial de 7 días y para grandfathering).
        await env.TRIAL_KV.put(key, now, { expirationTtl: 60 * 60 * 24 * 365 * 5 });
        return withCors(json({
          first_seen_at: now,
          days_since_first: 0,
          is_new: true,
        }));
      }

      return withCors(json({ error: "not_found", path }, 404));
    } catch (e) {
      return withCors(json({ error: "worker_exception", detail: String(e?.message || e) }, 500));
    }
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function withCors(response) {
  const h = new Headers(response.headers);
  h.set("Access-Control-Allow-Origin", "*");
  h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  h.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  return new Response(response.body, { status: response.status, headers: h });
}

function successHtml(deepLink, mode) {
  const safeLink = deepLink.replace(/"/g, "&quot;");
  const modeBadge = mode === "live"
    ? '<span style="background:#DC2626;color:#fff;padding:2px 8px;border-radius:8px;font-size:11px;font-weight:800;letter-spacing:0.06em">LIVE</span>'
    : '<span style="background:#6366F1;color:#fff;padding:2px 8px;border-radius:8px;font-size:11px;font-weight:800;letter-spacing:0.06em">TEST</span>';
  const html = `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Volver a Nexus Billings</title>
<style>
  *{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
       background:linear-gradient(135deg,#FFF7ED 0%,#FFEDD5 100%);
       display:flex;align-items:center;justify-content:center;min-height:100vh;
       margin:0;padding:20px}
  .card{background:#fff;border-radius:24px;padding:36px 28px;max-width:420px;
        width:100%;text-align:center;
        box-shadow:0 20px 60px rgba(234,88,12,0.18)}
  .icon{width:88px;height:88px;border-radius:44px;background:#D1FAE5;
        display:flex;align-items:center;justify-content:center;margin:0 auto 16px;
        font-size:48px}
  h1{color:#111827;margin:0 0 8px;font-size:26px;font-weight:800}
  p{color:#4B5563;line-height:1.55;margin:0 0 24px;font-size:15px}
  .btn{display:inline-block;background:#EA580C;color:#fff !important;
       padding:18px 32px;border-radius:14px;text-decoration:none;
       font-weight:800;font-size:17px;box-shadow:0 8px 24px rgba(234,88,12,0.35)}
  .btn:active{transform:scale(0.97)}
  .hint{margin-top:20px;font-size:12px;color:#9CA3AF}
</style></head>
<body>
<div class="card">
  <div class="icon">✅</div>
  <h1>¡Cuenta conectada! ${modeBadge}</h1>
  <p>Toca el botón para regresar a Nexus Billings y finalizar la vinculación.</p>
  <a class="btn" href="${safeLink}" id="openBtn">Volver a Nexus Billings →</a>
  <p class="hint">Si la app no abre, verifica que esté instalada.</p>
</div>
<script>
  setTimeout(function(){
    try { window.location.href = ${JSON.stringify(deepLink)}; } catch(e){}
  }, 800);
</script>
</body></html>`;
  return new Response(html, {
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function htmlError(title, detail) {
  const html = `<!doctype html>
<html lang="es"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Error de conexión</title>
<style>
  body{font-family:-apple-system,sans-serif;background:#FEE2E2;
       display:flex;align-items:center;justify-content:center;min-height:100vh;
       margin:0;padding:20px}
  .card{background:#fff;border-radius:16px;padding:24px;max-width:420px;
        box-shadow:0 4px 20px rgba(0,0,0,0.1);text-align:center}
  h1{color:#991B1B;font-size:20px;margin:0 0 12px}
  p{color:#7F1D1D;font-size:14px;margin:8px 0}
  code{display:block;background:#F3F4F6;padding:10px;border-radius:8px;
       font-size:11px;color:#374151;word-break:break-all;margin-top:12px}
</style></head>
<body><div class="card">
  <h1>❌ Error en la conexión</h1>
  <p>${escapeHtml(title)}</p>
  ${detail ? `<code>${escapeHtml(detail)}</code>` : ""}
  <p style="margin-top:16px;font-size:12px;color:#6B7280">
    Vuelve a la app y toca "Desvincular y reconectar" para intentar de nuevo.
  </p>
</div></body></html>`;
  return new Response(html, {
    status: 400,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

