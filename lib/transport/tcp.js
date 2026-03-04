/**
 * TCP Transport Layer
 * 
 * Base transport for HTTP connections.
 * Provides low-level socket operations with TLS support.
 */

import net from 'net';
import tls from 'tls';
import { ConnectionError, TimeoutError } from '../utils/errors.js';

/**
 * Maps Node socket/SSL error codes to user-friendly messages (used by translateSocketError).
 * @private
 */
const SOCKET_ERRORS = {
    'ECONNREFUSED': (host, port) =>
        `Connection refused at ${host}:${port}. Is the server running?`,

    'ENOTFOUND': (host) =>
        `Hostname not found: ${host}`,

    'ETIMEDOUT': (host, port) =>
        `Connection timeout at ${host}:${port}`,

    'ECONNRESET': () =>
        `Connection reset by server`,

    'EHOSTUNREACH': (host) =>
        `Host unreachable: ${host}`,

    'ENETUNREACH': () =>
        `Network unreachable`,

    'EADDRINUSE': (host, port) =>
        `Port ${port} already in use`,

    'EPIPE': () =>
        `Broken pipe - connection closed before sending all data`,

    'CERT_HAS_EXPIRED': () =>
        `SSL certificate has expired`,

    'UNABLE_TO_VERIFY_LEAF_SIGNATURE': () =>
        `SSL certificate verification failed`,

    'DEPTH_ZERO_SELF_SIGNED_CERT': () =>
        `Self-signed certificate detected`,
};

/**
 * Translate socket error to friendly message
 * @param {Error} err - Socket error
 * @param {string} host - Target host
 * @param {number} port - Target port
 * @returns {string}
 */
export function translateSocketError(err, host, port) {
    const handler = SOCKET_ERRORS[err.code];
    if (handler) {
        return handler(host, port);
    }
    return `Socket error: ${err.message} (code: ${err.code || 'unknown'})`;
}

/**
 * Create a TCP connection (with optional TLS)
 * @param {object} options - Connection options
 * @param {string} options.host - Target host
 * @param {number} options.port - Target port
 * @param {number} options.timeout - Connection timeout in ms
 * @param {boolean} options.secure - Use TLS
 * @param {boolean} options.rejectUnauthorized - Verify SSL certificates
 * @returns {Promise<net.Socket|tls.TLSSocket>} - Connected socket
 */
export function createConnection(options) {
    const {
        host,
        port,
        timeout = 10000,
        secure = false,
        rejectUnauthorized = false, // Default: ignore SSL errors (exploit mode)
    } = options;

    return new Promise((resolve, reject) => {
        let socket;

        if (secure) {
            // TLS connection
            socket = tls.connect({
                host,
                port,
                rejectUnauthorized,
                servername: host, // SNI
            }, () => {
                resolve(socket);
            });
        } else {
            // Plain TCP connection
            socket = new net.Socket();
            socket.connect(port, host, () => {
                resolve(socket);
            });
        }

        socket.setTimeout(timeout);

        socket.on('error', (err) => {
            const message = translateSocketError(err, host, port);
            reject(new ConnectionError(message, err.code, err));
        });

        socket.on('timeout', () => {
            socket.destroy();
            reject(new TimeoutError(
                `Connection timeout at ${host}:${port}`,
                timeout
            ));
        });
    });
}

/**
 * Send data and wait for complete response
 * Handles chunked responses and connection close
 * @param {net.Socket} socket - Connected socket
 * @param {Buffer|string} data - Data to send
 * @param {number} timeout - Response timeout in ms
 * @returns {Promise<Buffer>} - Response data
 */
export function sendAndReceive(socket, data, timeout = 10000) {
    return new Promise((resolve, reject) => {
        let response = Buffer.alloc(0);
        let responseTimeout;

        socket.setTimeout(timeout);

        // Send data
        socket.write(data, (err) => {
            if (err) {
                reject(new ConnectionError('Error sending data', 'WRITE_ERROR', err));
            }
        });

        // Collect response chunks
        socket.on('data', (chunk) => {
            response = Buffer.concat([response, chunk]);

            // Reset timeout on each chunk (for slow responses)
            if (responseTimeout) {
                clearTimeout(responseTimeout);
            }

            // Check if response seems complete (HTTP)
            if (isResponseComplete(response)) {
                socket.destroy();
                resolve(response);
            } else {
                // Set a shorter timeout for additional chunks
                responseTimeout = setTimeout(() => {
                    socket.destroy();
                    resolve(response);
                }, 500);
            }
        });

        socket.on('close', () => {
            if (responseTimeout) {
                clearTimeout(responseTimeout);
            }
            resolve(response);
        });

        socket.on('error', (err) => {
            if (responseTimeout) {
                clearTimeout(responseTimeout);
            }
            reject(new ConnectionError(err.message, err.code, err));
        });

        socket.on('timeout', () => {
            if (responseTimeout) {
                clearTimeout(responseTimeout);
            }
            socket.destroy();
            reject(new TimeoutError('Response timeout', timeout));
        });
    });
}

/**
 * Check if HTTP response is complete
 * @param {Buffer} data - Response data
 * @returns {boolean}
 */
function isResponseComplete(data) {
    const str = data.toString();

    // Check for Content-Length
    const contentLengthMatch = str.match(/Content-Length:\s*(\d+)/i);
    if (contentLengthMatch) {
        const contentLength = parseInt(contentLengthMatch[1]);
        const headerEnd = str.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
            const bodyLength = data.length - headerEnd - 4;
            return bodyLength >= contentLength;
        }
    }

    // Check for Transfer-Encoding: chunked
    if (/Transfer-Encoding:\s*chunked/i.test(str)) {
        // Chunked ends with 0\r\n\r\n
        return str.endsWith('0\r\n\r\n') || str.includes('\r\n0\r\n\r\n');
    }

    // Check for Connection: close (wait for socket close)
    if (/Connection:\s*close/i.test(str)) {
        return false;
    }

    return false;
}

