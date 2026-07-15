/**
 * HTTP Client with Session Support
 * 
 * Provides a high-level HTTP client similar to Python's requests.Session.
 * Features:
 * - Automatic cookie management
 * - SSL verification bypass
 * - Follow redirects
 * - Proxy support
 * - Base URL support
 */

import { createConnection, sendAndReceive, translateSocketError } from '../transport/tcp.js';
import { buildRequest, parseUrl, buildUrl, encodeFormData } from './request.js';
import { parseResponse } from './response.js';
import { CookieJar } from '../cookies/manager.js';
import {
    ConnectionError,
    TimeoutError,
    HttpError,
    ValidationError,
} from '../utils/errors.js';

/**
 * Default session options
 */
const DEFAULT_OPTIONS = {
    timeout: 30000,
    verify: false,           // SSL verification (false = ignore errors)
    followRedirects: true,
    maxRedirects: 10,
    headers: {},
    proxy: null,
};

/**
 * HTTP Session class
 * 
 * Similar to Python requests.Session - maintains cookies and settings
 * across multiple requests.
 */
export class Session {
    /**
     * Create a new HTTP session
     * @param {object} options - Session options
     * @param {number} options.timeout - Request timeout in ms
     * @param {boolean} options.verify - Verify SSL certificates
     * @param {boolean} options.followRedirects - Follow HTTP redirects
     * @param {number} options.maxRedirects - Maximum number of redirects
     * @param {Object} options.headers - Default headers for all requests
     * @param {Object} options.proxy - Proxy configuration { host, port }
     * @param {string} options.baseUrl - Base URL for relative requests
     */
    constructor(options = {}) {
        this.options = { ...DEFAULT_OPTIONS, ...options };
        this.cookies = new CookieJar();
        this.baseUrl = options.baseUrl || '';
        this.history = [];
    }

    /**
     * Resolve URL (handle base URL and relative paths)
     * @param {string} url - URL or path
     * @returns {object} - Parsed URL components
     */
    _resolveUrl(url) {
        // If it's already a full URL
        if (url.startsWith('http://') || url.startsWith('https://')) {
            return parseUrl(url);
        }

        // Use base URL
        if (this.baseUrl) {
            const base = parseUrl(this.baseUrl);

            // Handle absolute path
            if (url.startsWith('/')) {
                return {
                    ...base,
                    path: url,
                    query: '',
                };
            }

            // Handle relative path
            const basePath = base.path.endsWith('/') ? base.path : base.path + '/';
            return {
                ...base,
                path: basePath + url,
            };
        }

        throw new ValidationError('URL must be absolute or baseUrl must be set', 'url');
    }

    /**
     * Prepare request options
     * @param {string} method - HTTP method
     * @param {string} url - Request URL
     * @param {object} options - Request options
     * @returns {object} - Prepared request configuration
     */
    _prepareRequest(method, url, options = {}) {
        const urlInfo = this._resolveUrl(url);

        // Separate any query string already embedded in the path (can happen for
        // baseUrl + absolute path like '/y?z=9', where _resolveUrl keeps it on
        // the path) so params merge cleanly with a single '?'.
        let path = urlInfo.path;
        let query = urlInfo.query || '';
        const qIdx = path.indexOf('?');
        if (qIdx !== -1) {
            const embedded = path.slice(qIdx + 1);
            path = path.slice(0, qIdx);
            query = query ? `${query}&${embedded}` : embedded;
        }

        // Merge query string: params (object → url-encoded) on top of any query
        // already present in the URL, like requests' `params=`.
        if (options.params && typeof options.params === 'object') {
            const encoded = encodeFormData(options.params);
            if (encoded) {
                query = query ? `${query}&${encoded}` : encoded;
            }
        }

        // Merge headers
        const headers = {
            ...this.options.headers,
            ...options.headers,
        };

        // Get cookies for this request
        const cookieHeader = this.cookies.getCookieHeader(
            urlInfo.host,
            urlInfo.path,
            urlInfo.secure
        );

        // Build request options
        return {
            method: method.toUpperCase(),
            host: urlInfo.host,
            port: urlInfo.port,
            path: path + (query ? `?${query}` : ''),
            headers,
            body: options.body || options.data || null,
            formData: options.form || options.formData || null,
            files: options.files || null,
            cookies: cookieHeader,
            timeout: options.timeout || this.options.timeout,
            proxy: options.proxy || this.options.proxy,
            secure: urlInfo.secure,
            verify: options.verify !== undefined ? options.verify : this.options.verify,
        };
    }

    /**
     * Send HTTP request
     * @param {string} method - HTTP method
     * @param {string} url - Request URL
     * @param {object} [options] - Request options
     * @param {Object} [options.params] - Query string params (object → url-encoded), merged with any query already in the URL
     * @param {string|Object} [options.body] - Raw body (object → JSON), alias of options.data
     * @param {Object} [options.form] - URL-encoded form fields, alias of options.formData
     * @param {Object} [options.files] - Files for multipart upload { field: filePath }
     * @param {Object} [options.headers] - Per-request headers (merged over session headers)
     * @param {boolean} [options.followRedirects] - Override the session redirect behaviour for this call
     * @param {boolean} [options.verify] - Override SSL verification for this call
     * @param {number} [options.timeout] - Override timeout (ms) for this call
     * @returns {Promise<object>} - Parsed response
     */
    async request(method, url, options = {}) {
        const config = this._prepareRequest(method, url, options);
        let redirectCount = 0;
        let currentConfig = config;
        let currentUrl = url;

        // Per-request redirect toggle (falls back to the session default), so a
        // single call can inspect a 3XX without changing the session behaviour.
        const followRedirects = options.followRedirects !== undefined
            ? options.followRedirects
            : this.options.followRedirects;

        while (true) {
            try {
                // Build HTTP request
                const requestBuffer = buildRequest({
                    method: currentConfig.method,
                    host: currentConfig.host,
                    port: currentConfig.port,
                    path: currentConfig.path,
                    headers: currentConfig.headers,
                    body: currentConfig.body,
                    formData: currentConfig.formData,
                    files: currentConfig.files,
                    cookies: currentConfig.cookies,
                    useProxy: !!currentConfig.proxy,
                });

                // Determine connection target
                const connectHost = currentConfig.proxy
                    ? currentConfig.proxy.host
                    : currentConfig.host;
                const connectPort = currentConfig.proxy
                    ? currentConfig.proxy.port
                    : currentConfig.port;

                // Create connection
                const socket = await createConnection({
                    host: connectHost,
                    port: connectPort,
                    timeout: currentConfig.timeout,
                    secure: currentConfig.secure && !currentConfig.proxy,
                    rejectUnauthorized: currentConfig.verify,
                });

                // Send request and receive response
                const responseBuffer = await sendAndReceive(
                    socket,
                    requestBuffer,
                    currentConfig.timeout
                );

                // Parse response
                const response = parseResponse(responseBuffer);

                // Store cookies from response
                if (response.cookies.length > 0) {
                    this.cookies.addFromResponse(response.cookies, currentConfig.host);
                }

                // Add URL to response
                response.url = currentUrl;

                // Handle redirects
                if (response.isRedirect() && followRedirects) {
                    redirectCount++;

                    if (redirectCount > this.options.maxRedirects) {
                        throw new HttpError(
                            `Too many redirects (max: ${this.options.maxRedirects})`,
                            response.status,
                            response
                        );
                    }

                    const location = response.getLocation();
                    if (!location) {
                        throw new HttpError(
                            'Redirect response missing Location header',
                            response.status,
                            response
                        );
                    }

                    // Store in history
                    this.history.push({
                        url: currentUrl,
                        status: response.status,
                    });

                    // Resolve redirect URL
                    currentUrl = location.startsWith('http')
                        ? location
                        : buildUrl({
                            protocol: currentConfig.secure ? 'https' : 'http',
                            host: currentConfig.host,
                            port: currentConfig.port,
                            path: location,
                        });

                    // Prepare next request (GET for 301, 302, 303)
                    const nextMethod = [301, 302, 303].includes(response.status)
                        ? 'GET'
                        : currentConfig.method;

                    currentConfig = this._prepareRequest(nextMethod, currentUrl, {
                        ...options,
                        body: [301, 302, 303].includes(response.status) ? null : options.body,
                    });

                    continue;
                }

                // Return final response
                response.history = [...this.history];
                this.history = [];

                return response;

            } catch (err) {
                if (err instanceof ConnectionError ||
                    err instanceof TimeoutError ||
                    err instanceof HttpError) {
                    throw err;
                }

                // Translate socket error
                const message = translateSocketError(
                    err,
                    currentConfig.host,
                    currentConfig.port
                );
                throw new ConnectionError(message, err.code, err);
            }
        }
    }

    /**
     * GET request
     * @param {string} url - Request URL
     * @param {object} options - Request options
     * @returns {Promise<object>}
     */
    async get(url, options = {}) {
        return this.request('GET', url, options);
    }

    /**
     * POST request
     * @param {string} url - Request URL
     * @param {object} options - Request options
     * @returns {Promise<object>}
     */
    async post(url, options = {}) {
        return this.request('POST', url, options);
    }

    /**
     * PUT request
     * @param {string} url - Request URL
     * @param {object} options - Request options
     * @returns {Promise<object>}
     */
    async put(url, options = {}) {
        return this.request('PUT', url, options);
    }

    /**
     * DELETE request
     * @param {string} url - Request URL
     * @param {object} options - Request options
     * @returns {Promise<object>}
     */
    async delete(url, options = {}) {
        return this.request('DELETE', url, options);
    }

    /**
     * PATCH request
     * @param {string} url - Request URL
     * @param {object} options - Request options
     * @returns {Promise<object>}
     */
    async patch(url, options = {}) {
        return this.request('PATCH', url, options);
    }

    /**
     * HEAD request
     * @param {string} url - Request URL
     * @param {object} options - Request options
     * @returns {Promise<object>}
     */
    async head(url, options = {}) {
        return this.request('HEAD', url, options);
    }

    /**
     * OPTIONS request
     * @param {string} url - Request URL
     * @param {object} options - Request options
     * @returns {Promise<object>}
     */
    async options(url, options = {}) {
        return this.request('OPTIONS', url, options);
    }

    /**
     * Set a default header
     * @param {string} name - Header name
     * @param {string} value - Header value
     */
    setHeader(name, value) {
        this.options.headers[name] = value;
    }

    /**
     * Remove a default header
     * @param {string} name - Header name
     */
    removeHeader(name) {
        delete this.options.headers[name];
    }

    /**
     * Set proxy
     * @param {string} host - Proxy host
     * @param {number} port - Proxy port
     */
    setProxy(host, port) {
        this.options.proxy = { host, port };
    }

    /**
     * Clear proxy
     */
    clearProxy() {
        this.options.proxy = null;
    }

    /**
     * Set a cookie on the session jar in one line (like hardcoding an
     * authenticated cookie during development). Sent on the next matching
     * request. With no domain/path the cookie is sent to every host the
     * session talks to.
     * @param {string} name - Cookie name (e.g. 'PHPSESSID')
     * @param {string} value - Cookie value
     * @param {object} [opts] - Cookie attributes { domain, path, secure, httpOnly, expires, maxAge, sameSite }
     * @returns {Session} - this, for chaining
     */
    setCookie(name, value, opts = {}) {
        this.cookies.set(name, value, opts);
        return this;
    }

    /**
     * Get all cookies
     * @returns {Object}
     */
    getCookies() {
        return this.cookies.toObject();
    }

    /**
     * Clear all cookies
     */
    clearCookies() {
        this.cookies.clear();
    }

    /**
     * Save cookies to file
     * @param {string} filePath - File path
     */
    saveCookies(filePath) {
        this.cookies.save(filePath);
    }

    /**
     * Load cookies from file
     * @param {string} filePath - File path
     */
    loadCookies(filePath) {
        this.cookies.load(filePath);
    }
}

/**
 * Create a new session
 * @param {object} options - Session options
 * @returns {Session}
 */
export function createSession(options = {}) {
    return new Session(options);
}

/**
 * Quick GET request (no session)
 * @param {string} url - Request URL
 * @param {object} options - Request options
 * @returns {Promise<object>}
 */
export async function get(url, options = {}) {
    const session = new Session(options);
    return session.get(url, options);
}

/**
 * Quick POST request (no session)
 * @param {string} url - Request URL
 * @param {object} options - Request options
 * @returns {Promise<object>}
 */
export async function post(url, options = {}) {
    const session = new Session(options);
    return session.post(url, options);
}

