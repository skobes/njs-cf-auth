# njs_cf_auth

Validates auth tokens in the `Cf-Access-Jwt-Assertion` header. See [Validate JWTs](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/) for background.

Unlike Cloudflare's (Node.js) sample code, this module works with the [njs engine](https://nginx.org/en/docs/njs/engine.html).

1. Set up [nginx](https://nginx.org/en/docs/).
2. Install [nginx-module-njs](https://nginx.org/en/docs/njs/install.html).
3. Configure Cloudflare [tunnel](https://noted.lol/say-goodbye-to-reverse-proxy-and-hello-to-cloudflare-tunnels/) with access control.
4. Copy `njs_cf_auth.js` into `/etc/nginx/js/`.
5. Create `myapp.js` alongside it:

```js
export default {
  team_domain: "myteam.cloudflareaccess.com",
  aud: "(your Cloudflare AUD)",
  is_authorized: payload => {
    const email = payload.email;
    return email && email.endsWith("@mydomain.com");
  }
};
```

Put your custom auth logic in the callback (`payload` is a [JWT Claims Set](https://datatracker.ietf.org/doc/html/rfc7519); Cloudflare will pass the email from the [identity provider](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/)).

In `/etc/nginx/conf.d/default.conf`:

```nginx
js_path js;
js_import njs_cf_auth.js;
js_shared_dict_zone zone=cfauth:512K timeout=60s;
js_fetch_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
resolver 1.1.1.1;

server {
  ...
  location /protected/ {
    ...
    auth_request /auth_validate;
  }
  location /auth_validate {
    internal;
    js_import cf_app from myapp.js;
    js_content njs_cf_auth.validate;
  }
```

* Use `sudo nginx -s reload` to reload config.
* Logs are in `/var/log/nginx` by default.
* See [njs-examples](https://github.com/nginx/njs-examples/) to understand `auth_request`.
* The `js_fetch_trusted_certificate` and `resolver` directives are necessary for [`ngx.fetch()`](https://nginx.org/en/docs/njs/reference.html#ngx_fetch) to work.
* You may also want to [enable HTTPS](https://gist.github.com/mehmetsefabalik/257aab5a9ce69deb01f71d8b5be25256).
