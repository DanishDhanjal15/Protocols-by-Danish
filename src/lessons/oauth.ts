import { Device, defineLesson, note, pkt } from "@/lib/lesson";
import { rand, text } from "@/lib/bytes";
import { build, LayerSpec } from "@/lib/packet";
import { eth, ipv4, tcp, tls } from "@/lib/proto";
import { ADDR, down, up } from "./_common";

// ---------------------------------------------------------------- the cast
const APP = ADDR.web; // app.example.com, the photo app (OAuth client)
const IDP = ADDR.server2; // accounts.example-idp.com (authorization server + OpenID provider)
const API = "203.0.113.60"; // photos.example-idp.com (resource server)
const EVIL = "198.51.100.66";
const DC_GW = "00:16:3e:00:00:01";
const IDP_MAC = "00:16:3e:5a:02:40";

const CLIENT_ID = "photoapp-7f3a";
const REDIRECT = "https://app.example.com/callback";
const STATE = "af0ifjsldkj";
const NONCE = "n-0S6_WzA2Mj";
// The RFC 7636 example pair: challenge = BASE64URL(SHA256(verifier))
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CODE = "SplxlOBeZQQYbYS6WxSbIA";

// ---------------------------------------------------------------- tokens
const b64url = (s: string) => btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const randB64 = (n: number, seed: number) => b64url(String.fromCharCode(...rand(n, seed)));
const JWT_HEADER = { alg: "RS256", kid: "2026-11-a", typ: "JWT" };
const IAT = 1795078800; // 19 Nov 2026, 09:00 UTC
const JWT_PAYLOAD = {
  iss: "https://accounts.example-idp.com", sub: "248289761001", aud: CLIENT_ID, iat: IAT, exp: IAT + 3600,
  nonce: NONCE, email: "danish@example.com", email_verified: true, name: "Danish",
};
const ID_TOKEN = `${b64url(JSON.stringify(JWT_HEADER))}.${b64url(JSON.stringify(JWT_PAYLOAD))}.${randB64(256, 9001)}`;
const ACCESS = `at_${randB64(32, 9002)}`;
const ACCESS2 = `at_${randB64(32, 9004)}`;
const REFRESH = `rt_${randB64(32, 9003)}`;
const REFRESH2 = `rt_${randB64(32, 9005)}`;
const short = (s: string) => `${s.slice(0, 14)}…`;

const AUTHORIZE =
  `/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT)}` +
  `&scope=openid%20email%20profile%20photos.read&state=${STATE}&nonce=${NONCE}` +
  `&code_challenge=${CHALLENGE}&code_challenge_method=S256`;

// ---------------------------------------------------------------- packets
const t = (n: number) => Number(n.toFixed(4));
const size = (spec: LayerSpec) => build(spec).bytes.length;

/** One HTTPS message: the HTTP/1.1 text is encrypted in a TLS 1.3 record (text + 1 type byte + 16-byte tag). */
const https = (lines: string[], body = "") => {
  const msg = lines.join("\r\n") + "\r\n\r\n" + body;
  return tls({
    records: [{ type: "appdata", encrypted: text(msg).length + 17, what: `Encrypted HTTP: ${lines[0]}`, note: `Decrypted, this record holds:\n${msg}` }],
    summary: `TLS: Application Data (HTTP ${lines[0].split(" ").slice(0, 2).join(" ")})`,
  });
};

type Hop = { c2s: () => LayerSpec[]; s2c: () => LayerSpec[] };
const browserTo = (ip: string): Hop => ({ c2s: () => up(ip), s2c: () => down(ip) });
const appTo = (ip: string): Hop => ({
  c2s: () => [eth({ src: ADDR.serverMac, dst: DC_GW }), ipv4({ src: APP, dst: ip })],
  s2c: () => [eth({ src: DC_GW, dst: ADDR.serverMac }), ipv4({ src: ip, dst: APP, ttl: 58 })],
});
const evilToIdp: Hop = {
  c2s: () => [eth({ src: DC_GW, dst: IDP_MAC }), ipv4({ src: EVIL, dst: IDP, ttl: 49 })],
  s2c: () => [eth({ src: IDP_MAC, dst: DC_GW }), ipv4({ src: IDP, dst: EVIL })],
};

/** An already-open HTTPS connection (TCP and TLS handshakes done earlier). */
function conn(hop: Hop, sport: number, cBase: number, sBase: number, c0 = 518, s0 = 2741) {
  let c = c0;
  let s = s0;
  const seg = (fromClient: boolean, lines: string[], body = "") => {
    const payload = https(lines, body);
    const len = size(payload);
    const seq = fromClient ? c : s;
    const ack = fromClient ? s : c;
    const spec = tcp({ sport: fromClient ? sport : 443, dport: fromClient ? 443 : sport, seq, ack, flags: "PA", win: 502, seqBase: fromClient ? cBase : sBase, ackBase: fromClient ? sBase : cBase });
    if (fromClient) c += len; else s += len;
    return build(...(fromClient ? hop.c2s() : hop.s2c()), spec, payload);
  };
  return {
    req: (lines: string[], body = "") => seg(true, lines, body),
    res: (lines: string[], body = "") => seg(false, lines, body),
  };
}

const form = (o: Record<string, string>) => Object.entries(o).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
const json = (o: unknown) => JSON.stringify(o, null, 2);
const basic = `Basic ${btoa(`${CLIENT_ID}:s3cr3t-Kq9vX2`)}`;

// ---------------------------------------------------------------- normal flow
const bApp = conn(browserTo(APP), 52100, 0x11110000, 0x22220000);
const bIdp = conn(browserTo(IDP), 52101, 0x33330000, 0x44440000);
const aIdp = conn(appTo(IDP), 40200, 0x55550000, 0x66660000);
const aApi = conn(appTo(API), 40201, 0x77770000, 0x18880000);

const loginReq = bApp.req(["GET /login HTTP/1.1", "Host: app.example.com", "User-Agent: Mozilla/5.0", "Accept: text/html"]);
const loginRedirect = bApp.res([
  "HTTP/1.1 302 Found", `Location: https://accounts.example-idp.com${AUTHORIZE}`,
  "Set-Cookie: oauth_tx=Tx81kq; Secure; HttpOnly; SameSite=Lax", "Content-Length: 0",
]);
const authReq = bIdp.req([`GET ${AUTHORIZE} HTTP/1.1`, "Host: accounts.example-idp.com", "User-Agent: Mozilla/5.0", "Accept: text/html"]);
const authPage = bIdp.res(["HTTP/1.1 200 OK", "Content-Type: text/html; charset=utf-8", "Content-Length: 412"], `<html><body><h1>Sign in</h1><form method="post" action="/signin"><input name="email"><input name="password" type="password"><input type="hidden" name="tx" value="q7Hd2"><button>Next</button></form>${" ".repeat(240)}</body></html>`);
const signinBody = form({ email: "danish@example.com", password: "correct horse battery staple", tx: "q7Hd2" });
const signin = bIdp.req(["POST /signin HTTP/1.1", "Host: accounts.example-idp.com", "Content-Type: application/x-www-form-urlencoded", `Content-Length: ${signinBody.length}`], signinBody);
const consentPage = bIdp.res(["HTTP/1.1 200 OK", "Content-Type: text/html; charset=utf-8", "Set-Cookie: idp_session=Zk29fQ; Secure; HttpOnly", "Content-Length: 205"], `<html><body><p>Photo App wants to: see your email, see your profile, view your photos.</p><form method="post" action="/consent"><button name="ok" value="1">Allow</button></form></body></html>`);
const consentBody = form({ ok: "1", tx: "q7Hd2" });
const consent = bIdp.req(["POST /consent HTTP/1.1", "Host: accounts.example-idp.com", "Cookie: idp_session=Zk29fQ", "Content-Type: application/x-www-form-urlencoded", `Content-Length: ${consentBody.length}`], consentBody);
const codeRedirect = bIdp.res(["HTTP/1.1 302 Found", `Location: ${REDIRECT}?code=${CODE}&state=${STATE}`, "Content-Length: 0"]);
const callback = bApp.req([`GET /callback?code=${CODE}&state=${STATE} HTTP/1.1`, "Host: app.example.com", "Cookie: oauth_tx=Tx81kq", "Accept: text/html"]);
const tokenBody = form({ grant_type: "authorization_code", code: CODE, redirect_uri: REDIRECT, code_verifier: VERIFIER });
const tokenReq = aIdp.req(["POST /token HTTP/1.1", "Host: accounts.example-idp.com", `Authorization: ${basic}`, "Content-Type: application/x-www-form-urlencoded", `Content-Length: ${tokenBody.length}`], tokenBody);
const tokenJson = json({ access_token: ACCESS, token_type: "Bearer", expires_in: 3600, refresh_token: REFRESH, scope: "openid email profile photos.read", id_token: ID_TOKEN });
const tokenRes = aIdp.res(["HTTP/1.1 200 OK", "Content-Type: application/json", "Cache-Control: no-store", `Content-Length: ${tokenJson.length}`], tokenJson);
const home = bApp.res(["HTTP/1.1 302 Found", "Location: /home", "Set-Cookie: sid=G7q2Lx0pW; Secure; HttpOnly; SameSite=Lax", "Content-Length: 0"]);
const apiReq = aApi.req(["GET /v1/photos?limit=20 HTTP/1.1", "Host: photos.example-idp.com", `Authorization: Bearer ${ACCESS}`, "Accept: application/json"]);
const photosJson = json({ photos: [{ id: "p_1041", title: "Goa beach", taken: "2026-10-02" }, { id: "p_1042", title: "Diwali lights", taken: "2026-10-20" }], next: null });
const apiRes = aApi.res(["HTTP/1.1 200 OK", "Content-Type: application/json", `Content-Length: ${photosJson.length}`], photosJson);

// ---------------------------------------------------------------- stolen code
const sb = conn(browserTo(APP), 52300, 0x12340000, 0x56780000);
const ev = conn(evilToIdp, 61022, 0x0bad0000, 0x0ace0000, 1, 1);
const sCallback = sb.req([`GET /callback?code=${CODE}&state=${STATE} HTTP/1.1`, "Host: app.example.com", "Cookie: oauth_tx=Tx81kq", "Accept: text/html"]);
const evilBody = form({ grant_type: "authorization_code", code: CODE, redirect_uri: REDIRECT, client_id: CLIENT_ID });
const evilReq = ev.req(["POST /token HTTP/1.1", "Host: accounts.example-idp.com", "Content-Type: application/x-www-form-urlencoded", `Content-Length: ${evilBody.length}`], evilBody);
const evilErr = json({ error: "invalid_grant", error_description: "PKCE verification failed: code_verifier missing" });
const evilRes = ev.res(["HTTP/1.1 400 Bad Request", "Content-Type: application/json", "Cache-Control: no-store", `Content-Length: ${evilErr.length}`], evilErr);

// ---------------------------------------------------------------- refresh
const rApi = conn(appTo(API), 40400, 0x21210000, 0x43430000);
const rIdp = conn(appTo(IDP), 40401, 0x65650000, 0x87870000);
const oldCall = rApi.req(["GET /v1/photos?limit=20 HTTP/1.1", "Host: photos.example-idp.com", `Authorization: Bearer ${ACCESS}`, "Accept: application/json"]);
const expired = rApi.res(["HTTP/1.1 401 Unauthorized", 'WWW-Authenticate: Bearer error="invalid_token", error_description="The access token expired"', "Content-Length: 0"]);
const refreshBody = form({ grant_type: "refresh_token", refresh_token: REFRESH });
const refreshReq = rIdp.req(["POST /token HTTP/1.1", "Host: accounts.example-idp.com", `Authorization: ${basic}`, "Content-Type: application/x-www-form-urlencoded", `Content-Length: ${refreshBody.length}`], refreshBody);
const refreshJson = json({ access_token: ACCESS2, token_type: "Bearer", expires_in: 3600, refresh_token: REFRESH2, scope: "openid email profile photos.read" });
const refreshRes = rIdp.res(["HTTP/1.1 200 OK", "Content-Type: application/json", "Cache-Control: no-store", `Content-Length: ${refreshJson.length}`], refreshJson);
const retry = rApi.req(["GET /v1/photos?limit=20 HTTP/1.1", "Host: photos.example-idp.com", `Authorization: Bearer ${ACCESS2}`, "Accept: application/json"]);
const retryRes = rApi.res(["HTTP/1.1 200 OK", "Content-Type: application/json", `Content-Length: ${photosJson.length}`], photosJson);

// ---------------------------------------------------------------- stage
const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Browser", sub: ADDR.laptop, x: 8, y: 62 },
  { id: "router", kind: "router", label: "Home router", sub: ADDR.router, x: 27, y: 62 },
  { id: "internet", kind: "cloud", label: "Internet", x: 50, y: 42 },
  { id: "app", kind: "web", label: "app.example.com", sub: APP, x: 88, y: 78 },
  { id: "idp", kind: "auth", label: "accounts.example-idp.com", sub: IDP, x: 80, y: 18 },
  { id: "api", kind: "server", label: "Photos API", sub: API, x: 92, y: 48 },
];
const links: [string, string][] = [["client", "router"], ["router", "internet"], ["internet", "app"], ["internet", "idp"], ["internet", "api"]];
const attackDevices: Device[] = [...devices, { id: "evil", kind: "attacker", label: "Code thief", sub: EVIL, x: 30, y: 20 }];
const attackLinks: [string, string][] = [...links, ["evil", "internet"]];

const jwtHeaderText = JSON.stringify(JWT_HEADER);
const jwtPayloadText = JSON.stringify(JWT_PAYLOAD);

export default defineLesson({
  id: "oauth",
  name: "OAuth 2.0 + OIDC",
  full: "OAuth 2.0 Authorization Code with PKCE, and OpenID Connect",
  group: "security",
  layer: 7,
  difficulty: 3,
  tagline: "\"Sign in with…\": let an app in without giving it your password.",
  description:
    "OAuth 2.0 lets an app get limited access to your account at another service without ever seeing your password. OpenID Connect adds an ID token, a signed JWT that tells the app who you are. The authorization code flow with PKCE is the safe default for websites and mobile apps.",
  facts: [
    ["Layer", "Application (7), over HTTPS"],
    ["Main flow", "Authorization code + PKCE"],
    ["Tokens", "Access, refresh, ID (JWT)"],
    ["Front channel", "Browser redirects"],
    ["Back channel", "App → /token directly"],
    ["Defined in", "RFC 6749, RFC 7636, OIDC Core"],
  ],
  ports: "443 (everything runs over HTTPS)",
  rfc: "RFC 6749, RFC 7636 (PKCE), RFC 6750 (Bearer), OpenID Connect Core 1.0",
  keywords: ["oauth", "openid connect", "oidc", "sign in with google", "sso", "pkce", "jwt", "id token", "access token", "refresh token", "bearer", "authorization code", "consent"],
  related: ["tls", "http", "mtls", "kerberos"],
  devices,
  links,
  legend: [
    ["amber", "Browser requests"],
    ["violet", "Server replies and redirects"],
    ["teal", "Tokens (back channel)"],
    ["blue", "API calls"],
    ["red", "Errors and attacks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Sign in with example-idp",
      summary: "Danish signs in to a photo app with his example-idp account; the app gets tokens, never his password.",
      kind: "normal",
      steps: [
        {
          title: "Click 'Sign in'",
          desc: "The app redirects the browser to the identity provider",
          detail: `The app makes a secret random string, the code_verifier, and keeps it. It sends only its SHA-256 hash, the code_challenge, inside the redirect URL. The URL also has state (stops forged callbacks) and nonce (ties the ID token to this login). All traffic here is HTTPS; the packets show encrypted records, and the text describes the HTTP inside.`,
          facts: [["Response", "302 Found"], ["code_challenge", `${CHALLENGE.slice(0, 12)}… (S256)`], ["Kept secret", "code_verifier (in the app)"]],
          quiz: {
            q: "Why does the redirect carry the hash of the verifier instead of the verifier itself?",
            options: ["Hashes are shorter", "The URL passes through the browser and logs; only the app should ever know the verifier", "The identity provider can't read long strings", "To hide the client ID"],
            answer: 1,
            why: "Anything in a redirect URL can leak. The hash is useless on its own; later the app proves it started this login by revealing the original verifier.",
          },
          events: [
            pkt("client", "app", "amber", "GET /login", [], { time: 0, info: "Application Data (HTTP: GET /login)", packet: loginReq }),
            pkt("app", "client", "violet", "302", ["to /authorize", "+ code_challenge"], { time: 0.031, info: "Application Data (HTTP: 302 Found → /authorize)", packet: loginRedirect }),
          ],
        },
        {
          title: "The authorize request",
          desc: "The browser asks the identity provider",
          detail: "The browser follows the redirect to accounts.example-idp.com/authorize. The provider checks that client_id is registered and that redirect_uri exactly matches one on file, then shows its own sign-in page. The photo app never sees this page.",
          facts: [["response_type", "code"], ["scope", "openid email profile photos.read"], ["redirect_uri", "Must match exactly"]],
          events: [
            pkt("client", "idp", "amber", "AUTHORIZE", ["client_id, scope", "code_challenge"], { time: 0.033, info: "Application Data (HTTP: GET /authorize?response_type=code…)", packet: authReq }),
            pkt("idp", "client", "violet", "SIGN-IN PAGE", [], { time: 0.064, info: "Application Data (HTTP: 200 OK)", packet: authPage }),
          ],
        },
        {
          title: "Log in at the provider",
          desc: "The password goes only to example-idp",
          detail: "Danish types his email and password into the identity provider's page. The password travels to the provider and nowhere else. The provider may also ask for a second factor. It then shows a consent screen listing what the app wants.",
          facts: [["Password sent to", "Only the identity provider"], ["2FA", "Handled by the provider"], ["Next", "Consent screen"]],
          events: [
            pkt("client", "idp", "amber", "POST /signin", ["email + password"], { time: 6.2, info: "Application Data (HTTP: POST /signin)", packet: signin }),
            pkt("idp", "client", "violet", "CONSENT", ["Allow Photo App?"], { time: 6.31, info: "Application Data (HTTP: 200 OK)", packet: consentPage }),
          ],
        },
        {
          title: "Consent, then a code",
          desc: "Redirect back with a one-time authorization code",
          detail: `Danish clicks Allow. The provider redirects the browser to the app's callback with code=${CODE} and the same state. The code is short-lived (often 60 s) and single-use. The app checks that state matches the one it stored in the oauth_tx cookie.`,
          facts: [["Code", `${CODE.slice(0, 10)}…, single use`], ["Lifetime", "About 1 minute"], ["state", "Checked by the app"]],
          quiz: {
            q: "The code went through the browser and its address bar. What stops someone who sees it from using it?",
            options: ["Nothing; codes are public", "Exchanging it needs the code_verifier (and here a client secret)", "Codes only work on Sundays", "The state parameter"],
            answer: 1,
            why: "The /token endpoint only swaps a code for tokens if the caller presents the verifier whose hash was sent at the start. Confidential apps also authenticate with their own secret.",
          },
          events: [
            pkt("client", "idp", "amber", "ALLOW", [], { time: 8.9, info: "Application Data (HTTP: POST /consent)", packet: consent }),
            pkt("idp", "client", "violet", "302 + CODE", ["to app /callback"], { time: 8.94, info: "Application Data (HTTP: 302 Found → /callback?code=…)", packet: codeRedirect }),
            pkt("client", "app", "amber", "CALLBACK", ["code + state"], { time: 8.942, info: "Application Data (HTTP: GET /callback?code=…)", packet: callback }),
          ],
        },
        {
          title: "Back-channel token swap",
          desc: "The app trades the code and verifier for tokens",
          detail: "Now the app's server talks straight to the provider's /token endpoint; the browser is not involved. It sends the code, the redirect_uri, the code_verifier, and its own client credentials. The provider hashes the verifier, compares it with the stored challenge, and returns an access token, a refresh token and an ID token.",
          facts: [["Sends", "code + code_verifier + client auth"], ["Gets", "access, refresh and ID tokens"], ["Access token life", "3600 s"]],
          events: [
            pkt("app", "idp", "teal", "POST /token", ["code + verifier"], { time: 8.975, info: "Application Data (HTTP: POST /token)", packet: tokenReq }),
            pkt("idp", "app", "teal", "TOKENS", ["access, refresh", "id_token (JWT)"], { time: 8.984, info: "Application Data (HTTP: 200 OK, application/json)", packet: tokenRes }),
            note("idp", "VERIFIER ✓", "green"),
          ],
        },
        {
          title: "Read the ID token",
          desc: "A JWT that says who logged in",
          detail: `The ID token is three base64url parts joined by dots: header, payload, signature. Header decodes to ${jwtHeaderText}. Payload decodes to ${jwtPayloadText}. The app checks the RS256 signature with the provider's public key (kid 2026-11-a), then iss, aud, exp and nonce, and starts its own session.`,
          facts: [["sub", "248289761001 (stable user ID)"], ["aud", CLIENT_ID], ["Checked", "Signature, iss, aud, exp, nonce"]],
          quiz: {
            q: "The ID token's payload is only base64url-encoded, not encrypted. Why is that OK?",
            options: ["Nobody can decode base64", "It travels over HTTPS and the signature stops anyone changing it", "The payload is empty", "The browser deletes it"],
            answer: 1,
            why: "Base64url is just encoding. Secrecy comes from TLS on the back channel; integrity comes from the RS256 signature, which fails if one character changes.",
          },
          events: [
            note("app", "JWT SIGNATURE ✓", "green"),
            pkt("app", "client", "violet", "302 /home", ["session cookie"], { time: 8.986, info: "Application Data (HTTP: 302 Found → /home)", packet: home }),
          ],
        },
        {
          title: "Call the API",
          desc: "Bearer token on every request",
          detail: `To show Danish's photos, the app calls the Photos API with Authorization: Bearer ${short(ACCESS)}. The API checks the token is valid, not expired, and includes the photos.read scope. Whoever holds a bearer token can use it, which is why it must only ever travel over HTTPS.`,
          facts: [["Header", "Authorization: Bearer …"], ["Scope needed", "photos.read"], ["Result", "200 OK, 2 photos"]],
          events: [
            pkt("app", "api", "blue", "GET /photos", ["Bearer token"], { time: 9.0, info: "Application Data (HTTP: GET /v1/photos)", packet: apiReq }),
            pkt("api", "app", "blue", "200 OK", ["2 photos"], { time: 9.009, info: "Application Data (HTTP: 200 OK)", packet: apiRes }),
          ],
        },
      ],
      outro: {
        title: "Signed in without sharing a password",
        text: "The browser carried the app's request to the provider and brought back a one-time code. The app swapped that code, plus its PKCE verifier, for tokens over a direct back channel. The ID token says who Danish is; the access token lets the app read his photos and nothing more.",
        facts: [["Password seen by app", "Never"], ["Front channel", "Redirects with code"], ["Back channel", "Code + verifier → tokens"], ["Proof of identity", "Signed ID token (JWT)"]],
      },
    },
    {
      id: "stolen-code",
      name: "Stolen authorization code vs PKCE",
      summary: "A malicious browser extension copies the code from the callback URL and races to redeem it.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "The code leaks",
          desc: "A malicious extension reads the callback URL",
          detail: "Danish has a bad browser extension that can read every URL he visits. When the provider redirects to the callback, the extension copies the code and sends it to its owner. The same leak can happen through a mobile app that registers the same redirect scheme, or through logs.",
          facts: [["Leaked", "Authorization code + state"], ["Not leaked", "code_verifier (never left the app)"], ["Code valid for", "About 60 s"]],
          events: [
            pkt("client", "app", "amber", "CALLBACK", ["code + state"], { time: 0, info: "Application Data (HTTP: GET /callback?code=…)", packet: sCallback }),
            note("client", "CODE COPIED", "red"),
          ],
        },
        {
          title: "Without PKCE",
          desc: "What would happen on an old setup",
          detail: "If the app were a public client (a mobile or single-page app has no secret) and PKCE were not used, the code alone would be enough. The attacker would post it to /token with the public client_id and get Danish's access token. This was a real class of attack on mobile apps.",
          facts: [["Attacker needs", "Only the code"], ["Gets", "Access + refresh tokens"], ["Damage", "Full access to granted scopes"]],
          quiz: {
            q: "With PKCE in place, what does the attacker lack when calling /token?",
            options: ["The client_id", "The code_verifier whose hash was in the first redirect", "The redirect_uri", "An HTTPS connection"],
            answer: 1,
            why: "The verifier stayed in the app. The attacker only saw the challenge (a hash), and can't reverse SHA-256 to get the verifier.",
          },
          events: [note("evil", "CODE ALONE = TOKENS (NO PKCE)", "red")],
        },
        {
          title: "With PKCE: refused",
          desc: "invalid_grant: verifier missing",
          detail: "With PKCE, the provider stored the code_challenge when it issued the code. The attacker's request has no code_verifier, so the check fails and the provider answers 400 invalid_grant. Moments later the real app redeems the code normally. Good providers also revoke tokens if the same code is used twice.",
          facts: [["Response", "400 invalid_grant"], ["Reason", "No matching code_verifier"], ["Real app", "Succeeds"]],
          events: [
            pkt("evil", "idp", "red", "POST /token", ["stolen code", "no verifier"], { time: 0.4, info: "Application Data (HTTP: POST /token)", packet: evilReq }),
            pkt("idp", "evil", "red", "400", ["invalid_grant"], { time: 0.43, info: "Application Data (HTTP: 400 Bad Request)", packet: evilRes }),
            note("idp", "PKCE BLOCKED IT", "green"),
          ],
        },
      ],
      outro: {
        title: "A stolen code is worthless",
        text: "PKCE binds the code to the app that started the login: only the holder of the original verifier can redeem it. That is why OAuth 2.1 makes PKCE mandatory for every client, not just mobile apps.",
        facts: [["Attack", "Authorization code interception"], ["Defence", "PKCE (S256), exact redirect_uri, short code life"], ["Standard", "RFC 7636, OAuth 2.1"]],
      },
    },
    {
      id: "refresh",
      name: "Expired access token → refresh",
      summary: "An hour later the access token has expired; the app uses its refresh token to get a new one.",
      kind: "failure",
      steps: [
        {
          title: "401 from the API",
          desc: "The access token is over an hour old",
          detail: "Danish comes back after lunch. The app calls the Photos API with its old access token, but the token's exp has passed. The API replies 401 with a WWW-Authenticate header saying invalid_token: the token expired.",
          facts: [["Token age", "> 3600 s"], ["Response", "401 Unauthorized"], ["Header", 'WWW-Authenticate: Bearer error="invalid_token"']],
          quiz: {
            q: "What should the app do now?",
            options: ["Send Danish through the full login again at once", "Use the refresh token at /token to get a new access token", "Retry the same token until it works", "Ask Danish for his example-idp password"],
            answer: 1,
            why: "The refresh token exists for exactly this. It gets a fresh access token silently, with no redirect and no login page.",
          },
          events: [
            pkt("app", "api", "blue", "GET /photos", ["old token"], { time: 0, info: "Application Data (HTTP: GET /v1/photos)", packet: oldCall }),
            pkt("api", "app", "red", "401", ["token expired"], { time: 0.009, info: "Application Data (HTTP: 401 Unauthorized)", packet: expired }),
          ],
        },
        {
          title: "Use the refresh token",
          desc: "grant_type=refresh_token on the back channel",
          detail: "The app posts its refresh token and client credentials to /token. The provider checks the refresh token is still valid and not revoked, then returns a new access token. It also rotates the refresh token: the old one stops working, so a stolen copy is spotted if it is ever used.",
          facts: [["Grant", "refresh_token"], ["New access token", "3600 s"], ["Refresh token", "Rotated (old one dead)"]],
          events: [
            pkt("app", "idp", "teal", "REFRESH", ["refresh_token"], { time: 0.012, info: "Application Data (HTTP: POST /token)", packet: refreshReq }),
            pkt("idp", "app", "teal", "NEW TOKENS", ["access + refresh"], { time: 0.021, info: "Application Data (HTTP: 200 OK, application/json)", packet: refreshRes }),
          ],
        },
        {
          title: "Retry succeeds",
          desc: "Same call, new token",
          detail: "The app repeats the API call with the new bearer token and gets the photos. Danish never noticed anything. If the refresh token had been revoked (for example he removed the app's access in his account settings), the app would have had to send him through the login flow again.",
          facts: [["Result", "200 OK"], ["User saw", "Nothing"], ["If revoked", "Full login again"]],
          events: [
            pkt("app", "api", "blue", "GET /photos", ["new token"], { time: 0.024, info: "Application Data (HTTP: GET /v1/photos)", packet: retry }),
            pkt("api", "app", "blue", "200 OK", ["2 photos"], { time: 0.033, info: "Application Data (HTTP: 200 OK)", packet: retryRes }),
          ],
        },
      ],
      outro: {
        title: "Short-lived tokens, quietly renewed",
        text: "Access tokens are kept short-lived so a leaked one is useful only briefly. The refresh token, which never leaves the app's server, renews them behind the scenes and is rotated on every use.",
        facts: [["Access token", "Minutes to an hour"], ["Refresh token", "Days to months, rotated"], ["Expired token error", "401 invalid_token"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Endpoints",
      items: [["/authorize", "Browser: login, consent, returns a code"], ["/token", "Back channel: code or refresh token → tokens"], ["/userinfo", "OIDC: profile claims with the access token"], ["/.well-known/openid-configuration", "Discovery document"], ["/jwks", "Public keys to check ID token signatures"]],
    },
    {
      title: "Parameters",
      items: [["response_type=code", "Authorization code flow"], ["state", "Stops forged callbacks (CSRF)"], ["nonce", "Ties the ID token to this login"], ["code_challenge (S256)", "BASE64URL(SHA256(verifier))"], ["scope=openid", "Turns OAuth into OpenID Connect"]],
    },
    {
      title: "Tokens",
      items: [["Access token", "Sent to APIs as Bearer; short-lived"], ["Refresh token", "Gets new access tokens; keep on server"], ["ID token", "JWT about the user; for the app only"], ["Errors", "invalid_grant, invalid_client, invalid_token (401)"]],
    },
  ],
});
