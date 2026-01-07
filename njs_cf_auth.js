// njs_cf_auth.js
// nginx njs hook to validate Cloudflare JWT (see README.md).

const now = () => globalThis.mock_now || Date.now();
const b64_to_buf = b64 => Buffer.from(b64, "base64url");
const b64_to_json = b64 => JSON.parse(b64_to_buf(b64).toString());
const invalid_token = { code: 403 };
const cache_timeout_ms = 60000;

function parse_token(token) {
  const p = token.split(".");
  if (p.length != 3)
    return null;
  const header_b64 = p[0], payload_b64 = p[1], signature_b64 = p[2];
  try {
    return { header_b64, payload_b64, signature_b64,
             header: b64_to_json(header_b64),
             payload: b64_to_json(payload_b64),
             signature: b64_to_buf(signature_b64) };
  } catch (e) {
    return null;
  }
};

function check_claims(app, token) {
  const p = token.payload, now_sec = now() / 1000;
  return p &&
      p.iss == `https://${app.team_domain}` &&
      p.aud == app.aud &&
      (!p.exp || p.exp > now_sec) &&
      (!p.nbf || p.nbf < now_sec);
};

async function get_public_key(app, kid) {
  const get_cached = () => {
    const cached = ngx.shared.cfauth.get("keys");
    return cached && JSON.parse(cached).find(k => k.kid === kid);
  };
  const do_fetch = async () => {
    const res = await ngx.fetch(
        `https://${app.team_domain}/cdn-cgi/access/certs`);
    const keys = (await res.json()).keys;
    ngx.shared.cfauth.set("keys", JSON.stringify(keys), cache_timeout_ms);
    return keys.find(k => k.kid === kid);
  };
  const key = get_cached() || await do_fetch();
  if (!key || key.alg != "RS256")
    return null;
  return crypto.subtle.importKey("jwk", key,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      /* extractable */ false, [ "verify" ]);
};

async function is_signature_valid(app, token) {
  const kid = token.header && token.header.kid;
  if (!kid)
    return false;
  const key = await get_public_key(app, kid);
  if (!key)
    return false;
  const data = new TextEncoder().encode(
      `${token.header_b64}.${token.payload_b64}`);
  return crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5", key, token.signature, data);
};

async function do_validate(token) {
  const app = cf_app;
  if (!await is_signature_valid(app, token))
    return false;
  if (!check_claims(app, token))
    return false;
  return app.is_authorized(token.payload);
};

async function validate(r) {
  try {
    const token = r.headersIn["Cf-Access-Jwt-Assertion"];
    if (!token)
      throw invalid_token;

    const parsed = parse_token(token);
    if (!parsed)
      throw invalid_token;

    const success = await do_validate(parsed);
    r.return(success ? 200 : 403);
  } catch (e) {
    if (e !== invalid_token)
      console.error(e.stack || e);
    r.return(e.code || 500);
  }
};

export default { validate };
