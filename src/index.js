const APP_SCHEME_DEFAULT = "nexusbilling";
const APP_RETURN_PATH_DEFAULT = "stripe-return";
const STATE_MAX_AGE_S = 900;

function b64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64urlDecode(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const base64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const str = atob(base64);
  const arr = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i);
  return arr;
}

async function hmacSign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return b64urlEncode(new Uint8Array(sig));
}

async function hmacVerify(payload, sig, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  return await crypto.subtle.verify("HMAC", key, b64urlDecode(sig), new TextEncoder().encode(payload));
}

async function makeState(env, deviceId, mode = "test") {
  const payload = `${deviceId}:${mode}:${Math.floor(Date.now() / 1000)}`;
  const sig = await hmacSign(payload, env.HMAC_SECRET);
  return `${payload}.${sig}`;
}

async function verifyState(env, state) {
  const parts = state.split(".");
  if (parts.length !== 2) return null;
  const [payloadStr, sig] = parts;
  if (!(await hmacVerify(payloadStr, sig, env.HMAC_SECRET))) return null;
  const [deviceId, mode, tsStr] = payloadStr.split(":");
  const ts = parseInt(tsStr, 10);
  if (isNaN(ts) || Math.floor(Date.now() / 1000) - ts > STATE_MAX_AGE_S) return null;
  return { deviceId, mode, ts };
}

function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    status: init.status || 200,
    headers: { "Content-Type": "application/json; charset=utf-8", ...(init.headers || {}) },
  });
}

function corsHeaders(env, origin) {
  const allowed = (env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim());
  const allowOrigin = allowed.includes("*") || allowed.includes(origin) ? origin || "*" : allowed[0];
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

async function stripePost(env, path, bodyParams, stripeAccount) {
  const headers = {
    Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
    "Content-Type": "application/x-www-form-urlencoded",
  };
  if (stripeAccount) headers["Stripe-Account"] = stripeAccount;

  const res = await fetch(`https://api.stripe.com/v1${path}`, {
    method: "POST",
    headers,
    body: bodyParams.toString(),
  });
  const data = await res.json();
  return { ok: res.ok, status: res.status, data };
}

async function stripeGet(env, path, stripeAccount) {
  const headers = { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` };
  if (stripeAccount) headers["Stripe-Account"] = stripeAccount;

  const res = await fetch(`https://api.stripe.com/v1${path}`, { method: "GET", headers });
  const data = await res.json();
  return { ok: res.ok, status: res.status, data };
}

async function handleConnectUrl(request, env) {
  const body = await request.json().catch(() => ({}));
  const deviceId = (body.device_id || "").trim();
  if (!deviceId) return json({ error: "device_id_required" }, { status: 400 });

  const mode = body.mode === "live" ? "live" : "test";
  const state = await makeState(env, deviceId, mode);

  const params = new URLSearchParams({
    response_type: "code",
    client_id: env.STRIPE_CLIENT_ID,
    scope: "read_write",
    state,
  });

  return json({ url: `https://connect.stripe.com/oauth/authorize?${params.toString()}` });
}

async function handleOAuthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const err = url.searchParams.get("error");
  const errDesc = url.searchParams.get("error_description");

  const scheme = env.APP_SCHEME || APP_SCHEME_DEFAULT;
  const path = env.APP_RETURN_PATH || APP_RETURN_PATH_DEFAULT;

  function appBounce(qs) {
    const deepLink = `${scheme}://${path}?${qs.toString()}`;
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Nexus Billings</title><style>body{font-family:sans-serif;background:#1E293B;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}.card{background:#0F172A;padding:32px;border-radius:16px;text-align:center;border:1px solid #334155;max-width:400px}h1{font-size:22px;color:#22C55E}a{color:#38BDF8;text-decoration:none;font-weight:700}</style></head><body><div class="card"><h1>¡Conexión completada!</h1><p>Regresando a la aplicación Nexus Billings...</p><p><a href="${deepLink}">Toca aquí si no se abre automáticamente</a></p></div><script>window.location.replace("${deepLink}");</script></body></html>`;
    return new Response(html, { headers: { "Content-Type": "text/html" } });
  }

  if (err) return appBounce(new URLSearchParams({ status: "error", error: err, error_description: errDesc || "" }));
  if (!code || !state) return appBounce(new URLSearchParams({ status: "error", error: "missing_params" }));

  const payload = await verifyState(env, state);
  if (!payload) return appBounce(new URLSearchParams({ status: "error", error: "invalid_state" }));

  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_secret: env.STRIPE_SECRET_KEY,
  });

  const res = await fetch("https://connect.stripe.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  const data = await res.json();

  if (!res.ok) {
    return appBounce(
      new URLSearchParams({
        status: "error",
        error: data.error || "oauth_failed",
        error_description: data.error_description || "",
      })
    );
  }

  return appBounce(
    new URLSearchParams({
      status: "success",
      stripe_user_id: data.stripe_user_id || "",
      device_id: payload.deviceId,
    })
  );
}

async function handleAccountStatus(request, env) {
  const body = await request.json().catch(() => ({}));
  const acct = (body.account_id || "").trim();
  if (!acct || !acct.startsWith("acct_")) return json({ error: "invalid_account_id" }, { status: 400 });

  const { ok, status, data } = await stripeGet(env, `/accounts/${acct}`);
  if (!ok) return json({ error: "account_fetch_failed", detail: data }, { status });

  return json({
    connected: true,
    account_id: data.id,
    business_name: data.business_profile?.name || data.settings?.dashboard?.display_name || null,
    country: data.country || null,
    default_currency: data.default_currency || null,
    charges_enabled: !!data.charges_enabled,
    payouts_enabled: !!data.payouts_enabled,
    livemode: !!data.livemode,
  });
}

async function handleDeauthorize(request, env) {
  const body = await request.json().catch(() => ({}));
  const acct = (body.account_id || "").trim();
  if (!acct || !acct.startsWith("acct_")) return json({ error: "invalid_account_id" }, { status: 400 });

  const params = new URLSearchParams({ client_id: env.STRIPE_CLIENT_ID, stripe_user_id: acct });
  const { ok, status, data } = await stripePost(env, "/oauth/deauthorize", params);
  if (!ok) return json({ error: "deauthorize_failed", detail: data }, { status });

  return json({ ok: true, stripe_user_id: data.stripe_user_id });
}

async function handleCheckoutCreate(request, env) {
  const body = await request.json().catch(() => ({}));
  const acct = (body.account_id || "").trim();
  if (!acct || !acct.startsWith("acct_")) return json({ error: "invalid_account_id" }, { status: 400 });

  const amount = Number(body.amount) || 0;
  if (amount <= 0) return json({ error: "invalid_amount" }, { status: 400 });

  const currency = (body.currency || "usd").toLowerCase();
  const description = (body.description || "Invoice").slice(0, 200);
  const scheme = env.APP_SCHEME || APP_SCHEME_DEFAULT;

  const params = new URLSearchParams({
    mode: "payment",
    "success_url": `${scheme}://payment-success?session_id={CHECKOUT_SESSION_ID}`,
    "cancel_url": `${scheme}://payment-cancel`,
    "line_items[0][price_data][currency]": currency,
    "line_items[0][price_data][product_data][name]": description,
    "line_items[0][price_data][unit_amount]": String(Math.round(amount * 100)),
    "line_items[0][quantity]": "1",
  });

  if (body.customer_email) params.set("customer_email", body.customer_email);
  if (body.metadata && typeof body.metadata === "object") {
    for (const [k, v] of Object.entries(body.metadata)) {
      params.set(`metadata[${k}]`, String(v));
    }
  }

  const { ok, status, data } = await stripePost(env, "/checkout/sessions", params, acct);
  if (!ok) return json({ error: "checkout_failed", detail: data }, { status });

  return json({ url: data.url, data_id: data.id, expires_at: data.expires_at });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("origin") || "";
    const cors = corsHeaders(env, origin);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    if (!env.STRIPE_CLIENT_ID || !env.STRIPE_SECRET_KEY || !env.HMAC_SECRET) {
      return json({ error: "worker_misconfigured" }, { status: 500, headers: cors });
    }

    let res;
    try {
      if (url.pathname === "/") {
        res = json({ service: "nexus-stripe-oauth", version: "1.0.0", endpoints: ["/connect-url", "/oauth/callback", "/account/status", "/account/deauthorize", "/checkout"] });
      } else if (url.pathname === "/connect-url" && request.method === "POST") {
        res = await handleConnectUrl(request, env);
      } else if (url.pathname === "/oauth/callback" && request.method === "GET") {
        res = await handleOAuthCallback(request, env);
      } else if (url.pathname === "/account/status" && request.method === "POST") {
        res = await handleAccountStatus(request, env);
      } else if (url.pathname === "/account/deauthorize" && request.method === "POST") {
        res = await handleDeauthorize(request, env);
      } else if (url.pathname === "/checkout" && request.method === "POST") {
        res = await handleCheckoutCreate(request, env);
      } else {
        res = json({ error: "not_found" }, { status: 404 });
      }
    } catch (e) {
      res = json({ error: "internal_error", message: e.message }, { status: 500 });
    }

    for (const [k, v] of Object.entries(cors)) {
      res.headers.set(k, v);
    }

    return res;
  },
};

