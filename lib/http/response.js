/**
 * HTTP Response Parser
 * 
 * Parses raw HTTP responses into structured objects.
 * Handles various response formats and edge cases.
 */

import { ParseError } from '../utils/errors.js';

/**
 * @typedef {object} ParsedResponse
 * @property {boolean} ok - Whether the request was successful (2xx)
 * @property {number} status - HTTP status code
 * @property {string} statusText - HTTP status text
 * @property {Object} headers - Response headers (lowercase keys)
 * @property {string} body - Response body
 * @property {string} raw - Raw response string
 * @property {string[]} cookies - Set-Cookie values
 */

/**
 * Parse raw HTTP response
 * @param {string|Buffer} response - Raw HTTP response
 * @returns {ParsedResponse}
 * @throws {ParseError} If response is invalid
 */
export function parseResponse(response) {
    const raw = Buffer.isBuffer(response) ? response.toString() : response;

    if (!raw || raw.trim() === '') {
        throw new ParseError('Empty response received', raw);
    }

    // Split headers and body
    const headerEnd = raw.indexOf('\r\n\r\n');
    if (headerEnd === -1) {
        throw new ParseError('Invalid HTTP response: no header/body separator', raw);
    }

    const headerSection = raw.substring(0, headerEnd);
    const bodySection = raw.substring(headerEnd + 4);

    // Parse status line
    const lines = headerSection.split('\r\n');
    const statusLine = lines[0];

    const statusMatch = statusLine.match(/^HTTP\/[\d.]+\s+(\d+)\s*(.*)$/);
    if (!statusMatch) {
        throw new ParseError('Invalid HTTP response: bad status line', raw);
    }

    const status = parseInt(statusMatch[1]);
    const statusText = statusMatch[2] || '';

    // Parse headers
    const headers = {};
    const cookies = [];

    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        const colonIndex = line.indexOf(':');

        if (colonIndex > 0) {
            const key = line.substring(0, colonIndex).trim().toLowerCase();
            const value = line.substring(colonIndex + 1).trim();

            // Handle multiple values (like Set-Cookie)
            if (key === 'set-cookie') {
                cookies.push(value);
                if (headers[key]) {
                    if (Array.isArray(headers[key])) {
                        headers[key].push(value);
                    } else {
                        headers[key] = [headers[key], value];
                    }
                } else {
                    headers[key] = value;
                }
            } else {
                headers[key] = value;
            }
        }
    }

    // Handle chunked transfer encoding
    let body = bodySection;
    if (headers['transfer-encoding'] === 'chunked') {
        body = decodeChunked(bodySection);
    }

    return {
        ok: status >= 200 && status < 300,
        status,
        statusText,
        headers,
        body,
        raw,
        cookies,

        // Helper methods
        isSuccess() {
            return status >= 200 && status < 300;
        },

        isRedirect() {
            return status >= 300 && status < 400;
        },

        isClientError() {
            return status >= 400 && status < 500;
        },

        isServerError() {
            return status >= 500;
        },

        getHeader(name) {
            return headers[name.toLowerCase()];
        },

        getLocation() {
            return headers['location'] || null;
        },

        getContentType() {
            return headers['content-type'] || null;
        },

        json() {
            try {
                return JSON.parse(body);
            } catch (e) {
                throw new ParseError('Response is not valid JSON', body);
            }
        },

        text() {
            return body;
        },
    };
}

/**
 * Decode chunked transfer encoding
 * @param {string} data - Chunked body data
 * @returns {string} - Decoded body
 */
function decodeChunked(data) {
    let result = '';
    let remaining = data;

    while (remaining.length > 0) {
        // Find chunk size line
        const lineEnd = remaining.indexOf('\r\n');
        if (lineEnd === -1) break;

        const sizeLine = remaining.substring(0, lineEnd);
        const chunkSize = parseInt(sizeLine, 16);

        if (chunkSize === 0) break;
        if (isNaN(chunkSize)) break;

        // Extract chunk data
        const chunkStart = lineEnd + 2;
        const chunkEnd = chunkStart + chunkSize;

        if (chunkEnd > remaining.length) break;

        result += remaining.substring(chunkStart, chunkEnd);
        remaining = remaining.substring(chunkEnd + 2); // Skip \r\n after chunk
    }

    return result;
}

/**
 * Parse individual cookie string
 * @param {string} cookieString - Set-Cookie header value
 * @returns {object} - Parsed cookie object
 */
export function parseCookie(cookieString) {
    const parts = cookieString.split(';').map(p => p.trim());
    const [nameValue, ...attributes] = parts;

    const eqIndex = nameValue.indexOf('=');
    const name = eqIndex > 0 ? nameValue.substring(0, eqIndex).trim() : nameValue;
    const value = eqIndex > 0 ? nameValue.substring(eqIndex + 1).trim() : '';

    const cookie = {
        name,
        value,
        domain: '',
        path: '/',
        secure: false,
        httpOnly: false,
        expires: null,
        maxAge: null,
        sameSite: '',
    };

    for (const attr of attributes) {
        const [attrName, attrValue] = attr.split('=').map(s => s?.trim());
        const lowerName = attrName?.toLowerCase();

        switch (lowerName) {
            case 'domain':
                cookie.domain = attrValue || '';
                break;
            case 'path':
                cookie.path = attrValue || '/';
                break;
            case 'secure':
                cookie.secure = true;
                break;
            case 'httponly':
                cookie.httpOnly = true;
                break;
            case 'expires':
                cookie.expires = attrValue ? new Date(attrValue) : null;
                break;
            case 'max-age':
                cookie.maxAge = attrValue ? parseInt(attrValue) : null;
                break;
            case 'samesite':
                cookie.sameSite = attrValue || '';
                break;
        }
    }

    return cookie;
}

/**
 * Format cookies object for Cookie header
 * @param {Object} cookies - Cookies object { name: value }
 * @returns {string}
 */
export function formatCookieHeader(cookies) {
    if (!cookies || typeof cookies !== 'object') return '';

    return Object.entries(cookies)
        .map(([name, value]) => `${name}=${value}`)
        .join('; ');
}

