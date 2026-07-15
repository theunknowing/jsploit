/**
 * jsploit - Exploit Development Framework
 * 
 * A professional exploit development framework for Node.js.
 * Features:
 * - Session management (like Python requests.Session)
 * - Automatic cookie handling
 * - HTML parsing utilities
 * - SSL verification bypass
 * 
 * Uses only Node.js internal modules - no external dependencies.
 * 
 * @module jsploit
 */

import { createRequire } from 'module';

// Read version from package.json. Wrapped in try/catch so an esbuild
// single-file bundle (where '../package.json' isn't resolvable relative to the
// output) still loads — the version is cosmetic in that case.
let version = '0.0.0';
try {
    const require = createRequire(import.meta.url);
    version = require('../package.json').version;
} catch {
    // Bundled build: package.json unavailable; fall back to a placeholder.
}

/**
 * Library version (synced from package.json; '0.0.0' in a standalone bundle)
 */
export const VERSION = version;

// ─────────────────────────────────────────────────────────────
// Core Exports
// ─────────────────────────────────────────────────────────────

/** HTTP Session (main entry point). Session, createSession, get, post for stateful requests with cookies and baseUrl. */
export { Session, createSession, get, post } from './http/client.js';

/** HTML Parsing. parse(), HTMLDocument, FormElement, findCSRFToken(), findForm() for regex-based extraction without external deps. */
export { parse, HTMLDocument, FormElement, findCSRFToken, findForm } from './html/parser.js';

// ─────────────────────────────────────────────────────────────
// Listener (payload server + hit capture + LHOST discovery)
// ─────────────────────────────────────────────────────────────

/** Payload server + hit capture. PayloadServer serves payload.js/beacons and captures the callback (waitForHit/'hit'). GIF_1x1 is a ready `<img>` beacon body. */
export { PayloadServer, GIF_1x1 } from './listener/http-server.js';

/** LHOST discovery. getLHOST({ iface, forTarget }) finds the VPN (tun0) IPv4 the payload should call back to; getLHOSTAsync awaits route-based discovery. */
export { getLHOST, getLHOSTAsync } from './listener/netinfo.js';

// ─────────────────────────────────────────────────────────────
// Blind (parallel character-by-character extraction)
// ─────────────────────────────────────────────────────────────

/** Blind extraction. extractBlind({ oracle, strategy, mode, ... }) reconstructs an unknown string via a user oracle — linear/binary × boolean/time, parallelized by position. */
export { extractBlind } from './blind/parallel.js';

// ─────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────

/** Logger. default logger, LOG_LEVELS, setLogLevel, getLogLevel for exploit output. */
export { default as logger, LOG_LEVELS, setLogLevel, getLogLevel } from './utils/logger.js';

/** Colors. colors, disableColors, colorize for terminal output. */
export { colors, disableColors, colorize } from './utils/colors.js';

/** Errors. EXIT_CODES and error classes (ValidationError, ConnectionError, HttpError, etc.) used by CLI and Session. */
export {
    EXIT_CODES,
    JsploitError,
    ValidationError,
    ConnectionError,
    HttpError,
    TimeoutError,
    ParseError,
    ExploitError,
    ListenerError,
} from './utils/errors.js';

// ─────────────────────────────────────────────────────────────
// Advanced Exports (for custom implementations)
// ─────────────────────────────────────────────────────────────

/** Cookie management. CookieJar and createCookieJar for domain/path-scoped cookie storage. */
export { CookieJar, createCookieJar } from './cookies/manager.js';

/** HTTP request building. buildRequest, parseUrl, buildUrl, encodeFormData, CONTENT_TYPES for raw HTTP. */
export {
    buildRequest,
    parseUrl,
    buildUrl,
    encodeFormData,
    CONTENT_TYPES,
} from './http/request.js';

/** HTTP response parsing. parseResponse, parseCookie, formatCookieHeader for raw response handling. */
export {
    parseResponse,
    parseCookie,
    formatCookieHeader,
} from './http/response.js';

/** Transport layer. createConnection, sendAndReceive, translateSocketError for TCP/TLS sockets. */
export {
    createConnection,
    sendAndReceive,
    translateSocketError,
} from './transport/tcp.js';

