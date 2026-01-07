#!/usr/bin/njs

import auth from "./njs_cf_auth.js";

async function tests(map) {
  for (const name in map) {
    try {
      await map[name]();
      console.log(`PASS: ${name}`);
    }
    catch (e) { console.error(`FAILED: ${name}\n${e.stack}`); }
  }
};

function assert_equals(a, b) {
  if (a != b) { throw new Error(`${a} != ${b}`); }
};

// Example generated with https://www.scottbrady.io/tools/jwt
const sample_jwt = {
  token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImI2MDZkOGJjYzM4NjZjN" +
      "WU1NzMzYWUxZmU3NGM2NmNmIn0.eyJpc3MiOiJodHRwczovL215dGVhbS5jbG91ZGZsY" +
      "XJlYWNjZXNzLmNvbSIsImF1ZCI6Im15X2FwcF9hdWQiLCJlbWFpbCI6ImpvaG5kb2VAZ" +
      "XhhbXBsZS5jb20iLCJleHAiOjE3NTU3MzkzMTEsImlhdCI6MTc1NTczOTAxMX0.dNpyX" +
      "hY04YufqLuK9XX1hz6OytehvdU5aXOPGo3Om0D5oMySmdp2JyIkPlGCVyCnf0MD2bI7V" +
      "2-ktMPtfMANodsCDa1fEqEh6zN3cpZVK3HS4L7QRqzr6wAtC7JFiFul9K_DrPHXVaC-I" +
      "2IwYna9mWmHj3awmkS8Qj_5unPbDl7YhYv0ITBzpdzRPC6rJ1L07bbHzAJy4hKjEuhPY" +
      "Y9tIbEKWBt7S-5d4CZbUHmhcg6sjCSuP6AWz4o3HLnX85xMRPr13TmEEumnSprTgLv69" +
      "DfbG6wn6sYsEXnKuiAQrBhzrf6LYzCcAA_gVxpIZgP9D6ndH3BWHR5DvV0tA2zvhQ",
  certs: '{ "keys": [ { ' +
      '"alg": "RS256", "e": "AQAB", "key_ops": [ "verify" ], "kty": "RSA", ' +
      '"n": "iAIexFASgwN1ox38ysHYvHo4ZdhZZ-G2yOnowSYAKqmCpPUC2Rt5wOBJTaaA3e' +
            'nwL5ceJWoroL5Tf1Pv3PuPzaFSOech9XdCXEtSN7deQqm7h2zuba-_3H5SIKaD' +
            'U8AK5KaqrqgrSrR26RgeHEy62C4nOgyshHgwHVcRfzP0sMnsFRgZdH-LwaIyXv' +
            'IRt4pLuZjM-4-oJGw0d8i_xTu2F8lU0Jtv7b5QmBSlEwPixipqvVx_0gHybMhj' +
            'ddUp1wVF8jhUAjvX-kf0u7C0NcDkyRUVoRC5SM16xfrUyg9kM9t9xvHY0iXVq2' +
            'fQOcd_s32emBjodKb9FQsQrXrwePIK9w", ' +
      '"use": "sig", "kid": "b606d8bcc3866c5e5733ae1fe74c66cf" } ] }',
  team: "myteam",
  aud: "my_app_aud",
  email: "johndoe@example.com",
  now: 1755739201111
};
const team_domain = `${sample_jwt.team}.cloudflareaccess.com`;
const cert_url = `https://${team_domain}/cdn-cgi/access/certs`;
const cache = {};
const cf_app = {
  team_domain: team_domain,
  aud: sample_jwt.aud,
  is_authorized: p => p.email == sample_jwt.email
};

let fetch_count = 0, last_code = 0, fetched_url = null;

const mock_ngx = {
  fetch: async url => {
    fetch_count++;
    fetched_url = url;
    return { json: async () => JSON.parse(sample_jwt.certs) };
  },
  shared: {
    cfauth: {
      get: key => cache[key],
      set: (key, val) => { cache[key] = val; }
    }
  }
};

function create_mock_request(token) {
  let headers = {};
  if (token)
    headers["Cf-Access-Jwt-Assertion"] = token;
  return {
    headersIn: headers,
    return: code => { last_code = code; }
  };
};

globalThis.mock_now = sample_jwt.now;
globalThis.cf_app = cf_app;
globalThis.ngx = mock_ngx;

tests({
  "validate sample": async () => {
    const r = create_mock_request(sample_jwt.token);
    await auth.validate(r);
    assert_equals(last_code, 200);
    assert_equals(fetched_url, cert_url);
  },

  "missing token": async () => {
    await auth.validate(create_mock_request());
    assert_equals(last_code, 403);
  },

  "invalid token": async () => {
    await auth.validate(create_mock_request("invalid"));
    assert_equals(last_code, 403);
  },

  "unauthorized user": async () => {
    const r = create_mock_request(sample_jwt.token);
    const e = sample_jwt.email;
    sample_jwt.email = "janedoe@example.com";
    await auth.validate(r);
    assert_equals(last_code, 403);
    sample_jwt.email = e;
  },

  "cached keys": async () => {
    const r = create_mock_request(sample_jwt.token);
    await auth.validate(r);
    assert_equals(last_code, 200);
    assert_equals(fetch_count, 1);

    cache.keys = '[{"kid":"bad"}]';
    await auth.validate(r);
    assert_equals(last_code, 200);
    assert_equals(fetch_count, 2);
  },

  "expired token": async () => {
    const r = create_mock_request(sample_jwt.token);
    globalThis.mock_now = 1755739401111;
    await auth.validate(r);
    assert_equals(last_code, 403);
  }
});
