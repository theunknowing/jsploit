/**
 * Custom error classes for jsploit
 * 
 * Hierarchy:
 *   JsploitError (base)
 *   ├── ValidationError  - Invalid input parameters
 *   ├── ConnectionError  - Network/socket errors
 *   ├── HttpError        - HTTP protocol errors
 *   ├── TimeoutError     - Connection/response timeouts
 *   ├── ParseError       - HTML/response parsing errors
 *   └── ExploitError     - Exploit execution errors
 */

/**
 * Exit codes returned by the CLI (process.exit). Match error types for programmatic handling.
 */
export const EXIT_CODES = {
    SUCCESS: 0,
    VALIDATION_ERROR: 1,
    CONNECTION_ERROR: 2,
    HTTP_ERROR: 3,
    TIMEOUT_ERROR: 4,
    PARSE_ERROR: 5,
    EXPLOIT_ERROR: 6,
    UNKNOWN_ERROR: 99,
};

/**
 * Base error class for all jsploit errors.
 * @param {string} message - Error message
 * @param {string} [code='JSPLOIT_ERROR'] - Error code
 */
export class JsploitError extends Error {
    constructor(message, code = 'JSPLOIT_ERROR') {
        super(message);
        this.name = 'JsploitError';
        this.code = code;
    }
}

/**
 * Validation error - invalid input parameters (e.g. missing target URL).
 * @param {string} message - Error message
 * @param {string|null} [field=null] - Field that failed validation
 */
export class ValidationError extends JsploitError {
    constructor(message, field = null) {
        super(message, 'VALIDATION_ERROR');
        this.name = 'ValidationError';
        this.field = field;
    }
}

/**
 * Connection error - network/socket errors (e.g. ECONNREFUSED, timeout).
 * @param {string} message - Error message
 * @param {string} [code='CONNECTION_ERROR'] - Error code
 * @param {Error|null} [cause=null] - Original error
 */
export class ConnectionError extends JsploitError {
    constructor(message, code = 'CONNECTION_ERROR', cause = null) {
        super(message, code);
        this.name = 'ConnectionError';
        this.cause = cause;
    }
}

/**
 * HTTP error - protocol errors (4xx, 5xx). statusCode and response available for handling.
 * @param {string} message - Error message
 * @param {number} [statusCode=0] - HTTP status code
 * @param {object|null} [response=null] - Parsed response object
 */
export class HttpError extends JsploitError {
    constructor(message, statusCode = 0, response = null) {
        super(message, 'HTTP_ERROR');
        this.name = 'HttpError';
        this.statusCode = statusCode;
        this.response = response;
    }
}

/**
 * Timeout error - connection or response timeout exceeded.
 * @param {string} message - Error message
 * @param {number} [timeout=0] - Timeout value in ms
 */
export class TimeoutError extends JsploitError {
    constructor(message, timeout = 0) {
        super(message, 'TIMEOUT_ERROR');
        this.name = 'TimeoutError';
        this.timeout = timeout;
    }
}

/**
 * Parse error - HTML or response parsing failed (e.g. invalid HTTP, bad JSON).
 * @param {string} message - Error message
 * @param {string|object|null} [content=null] - Raw content that failed to parse
 */
export class ParseError extends JsploitError {
    constructor(message, content = null) {
        super(message, 'PARSE_ERROR');
        this.name = 'ParseError';
        this.content = content;
    }
}

/**
 * Exploit error - exploit script or execution failed (e.g. validation inside exploit).
 * @param {string} message - Error message
 * @param {string|null} [step=null] - Step or phase where it failed
 * @param {*} [details=null] - Additional details
 */
export class ExploitError extends JsploitError {
    constructor(message, step = null, details = null) {
        super(message, 'EXPLOIT_ERROR');
        this.name = 'ExploitError';
        this.step = step;
        this.details = details;
    }
}

