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

// Read version from package.json
const require = createRequire(import.meta.url);
const pkg = require('../package.json');

/**
 * Library version (synced from package.json)
 */
export const VERSION = pkg.version;

// ─────────────────────────────────────────────────────────────
// Core Exports
// ─────────────────────────────────────────────────────────────

/** HTTP Session (main entry point). Session, createSession, get, post for stateful requests with cookies and baseUrl. */
export { Session, createSession, get, post } from './http/client.js';

/** HTML Parsing. parse(), HTMLDocument, FormElement, findCSRFToken(), findForm() for regex-based extraction without external deps. */
export { parse, HTMLDocument, FormElement, findCSRFToken, findForm } from './html/parser.js';

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

