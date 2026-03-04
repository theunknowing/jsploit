/**
 * HTTP Request Builder
 * 
 * Constructs raw HTTP requests for sending over sockets.
 * Supports form data, JSON, and custom content types.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * Common content types
 */
export const CONTENT_TYPES = {
    FORM: 'application/x-www-form-urlencoded',
    JSON: 'application/json',
    MULTIPART: 'multipart/form-data',
    TEXT: 'text/plain',
    HTML: 'text/html',
};

/**
 * Generate unique boundary for multipart requests
 * @returns {string}
 */
function generateBoundary() {
    return '----jsploit' + crypto.randomBytes(16).toString('hex');
}

/**
 * Check if header exists (case-insensitive)
 * @param {Object} headers - Headers object
 * @param {string} name - Header name to check
 * @returns {boolean}
 */
function hasHeader(headers, name) {
    const lowerName = name.toLowerCase();
    return Object.keys(headers).some(h => h.toLowerCase() === lowerName);
}

/**
 * Get header value (case-insensitive)
 * @param {Object} headers - Headers object
 * @param {string} name - Header name
 * @returns {string|undefined}
 */
function getHeader(headers, name) {
    const lowerName = name.toLowerCase();
    const key = Object.keys(headers).find(h => h.toLowerCase() === lowerName);
    return key ? headers[key] : undefined;
}

/**
 * Encode object as URL-encoded form data
 * @param {Object} data - Data to encode
 * @returns {string}
 */
export function encodeFormData(data) {
    if (typeof data === 'string') return data;

    return Object.entries(data)
        .map(([key, value]) => {
            const encodedKey = encodeURIComponent(key);
            const encodedValue = encodeURIComponent(String(value));
            return `${encodedKey}=${encodedValue}`;
        })
        .join('&');
}

/**
 * Build multipart/form-data body
 * @param {Object} fields - Form fields
 * @param {Object} files - File uploads { fieldName: filePath }
 * @param {string} boundary - Boundary string
 * @returns {Buffer}
 */
export function buildMultipartBody(fields, files = {}, boundary) {
    const parts = [];

    // Add regular fields
    for (const [name, value] of Object.entries(fields)) {
        parts.push(Buffer.from(
            `--${boundary}\r\n` +
            `Content-Disposition: form-data; name="${name}"\r\n\r\n` +
            `${value}\r\n`
        ));
    }

    // Add file fields
    for (const [name, filePath] of Object.entries(files)) {
        const fileName = path.basename(filePath);
        const fileContent = fs.readFileSync(filePath);

        parts.push(Buffer.from(
            `--${boundary}\r\n` +
            `Content-Disposition: form-data; name="${name}"; filename="${fileName}"\r\n` +
            `Content-Type: application/octet-stream\r\n\r\n`
        ));
        parts.push(fileContent);
        parts.push(Buffer.from('\r\n'));
    }

    // Final boundary
    parts.push(Buffer.from(`--${boundary}--\r\n`));

    return Buffer.concat(parts);
}

/**
 * Build raw HTTP request buffer.
 * Sets Content-Type from formData/body (url-encoded, JSON, or multipart). When useProxy is true,
 * request line is "METHOD http://host:port/path HTTP/1.1" for CONNECT-style proxies.
 * @param {object} options - Request options
 * @param {string} options.method - HTTP method
 * @param {string} options.host - Target host
 * @param {number} options.port - Target port
 * @param {string} options.path - Request path
 * @param {Object} options.headers - Custom headers
 * @param {string|Object} options.body - Request body
 * @param {Object} options.formData - Form fields for multipart
 * @param {Object} options.files - Files for multipart
 * @param {string} options.cookies - Cookie header value
 * @param {boolean} options.useProxy - Use absolute URL in request line (for proxy)
 * @returns {Buffer}
 */
export function buildRequest(options) {
    const {
        method = 'GET',
        host,
        port = 80,
        path = '/',
        headers = {},
        body = null,
        formData = null,
        files = null,
        cookies = '',
        useProxy = false,
    } = options;

    // Clone headers to avoid mutation
    const requestHeaders = { ...headers };

    // Request line
    const requestLine = useProxy
        ? `${method.toUpperCase()} http://${host}:${port}${path} HTTP/1.1`
        : `${method.toUpperCase()} ${path} HTTP/1.1`;

    // Start building headers
    let headerSection = `${requestLine}\r\n`;
    headerSection += `Host: ${host}\r\n`;

    // Connection header (keep-alive for session reuse)
    if (!hasHeader(requestHeaders, 'Connection')) {
        headerSection += `Connection: close\r\n`;
    }

    // User-Agent
    if (!hasHeader(requestHeaders, 'User-Agent')) {
        headerSection += `User-Agent: jsploit/1.0\r\n`;
    }

    // Cookies
    if (cookies) {
        headerSection += `Cookie: ${cookies}\r\n`;
    }

    // Determine body content
    let bodyBuffer = null;

    if (formData && files) {
        // Multipart form-data with files
        const boundary = generateBoundary();
        bodyBuffer = buildMultipartBody(formData, files, boundary);

        if (!hasHeader(requestHeaders, 'Content-Type')) {
            requestHeaders['Content-Type'] = `multipart/form-data; boundary=${boundary}`;
        }
    } else if (formData) {
        // URL-encoded form data
        bodyBuffer = Buffer.from(encodeFormData(formData));

        if (!hasHeader(requestHeaders, 'Content-Type')) {
            requestHeaders['Content-Type'] = CONTENT_TYPES.FORM;
        }
    } else if (body) {
        // Raw body
        if (typeof body === 'object') {
            bodyBuffer = Buffer.from(JSON.stringify(body));
            if (!hasHeader(requestHeaders, 'Content-Type')) {
                requestHeaders['Content-Type'] = CONTENT_TYPES.JSON;
            }
        } else {
            bodyBuffer = Buffer.from(body);
        }
    }

    // Add custom headers
    for (const [key, value] of Object.entries(requestHeaders)) {
        headerSection += `${key}: ${value}\r\n`;
    }

    // Content-Length
    if (bodyBuffer) {
        headerSection += `Content-Length: ${bodyBuffer.length}\r\n`;
    }

    // End headers
    headerSection += '\r\n';

    // Combine headers and body
    if (bodyBuffer) {
        return Buffer.concat([Buffer.from(headerSection), bodyBuffer]);
    }

    return Buffer.from(headerSection);
}

/**
 * Parse URL string into components
 * @param {string} url - URL to parse
 * @returns {object} - { protocol, host, port, path, query }
 */
export function parseUrl(url) {
    const result = {
        protocol: 'http',
        host: '',
        port: 80,
        path: '/',
        query: '',
        secure: false,
    };

    let remaining = url.trim();

    // Extract protocol
    const protocolMatch = remaining.match(/^(https?):\/\//);
    if (protocolMatch) {
        result.protocol = protocolMatch[1];
        result.secure = result.protocol === 'https';
        result.port = result.secure ? 443 : 80;
        remaining = remaining.replace(/^https?:\/\//, '');
    }

    // Extract path and query
    const pathIndex = remaining.indexOf('/');
    if (pathIndex !== -1) {
        const pathPart = remaining.substring(pathIndex);
        remaining = remaining.substring(0, pathIndex);

        const queryIndex = pathPart.indexOf('?');
        if (queryIndex !== -1) {
            result.path = pathPart.substring(0, queryIndex);
            result.query = pathPart.substring(queryIndex + 1);
        } else {
            result.path = pathPart;
        }
    }

    // Extract port
    const portMatch = remaining.match(/:(\d+)$/);
    if (portMatch) {
        result.port = parseInt(portMatch[1]);
        remaining = remaining.replace(/:\d+$/, '');
    }

    result.host = remaining;

    return result;
}

/**
 * Build full URL from components
 * @param {object} parts - URL parts
 * @returns {string}
 */
export function buildUrl(parts) {
    const { protocol = 'http', host, port, path = '/', query = '' } = parts;

    const defaultPort = protocol === 'https' ? 443 : 80;
    const portStr = port && port !== defaultPort ? `:${port}` : '';
    const queryStr = query ? `?${query}` : '';

    return `${protocol}://${host}${portStr}${path}${queryStr}`;
}

