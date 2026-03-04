/**
 * Logger utility with colors and levels
 * 
 * Provides consistent logging across the application
 * with color-coded prefixes and various output formats.
 */

import { colors } from './colors.js';

/**
 * Log levels
 */
export const LOG_LEVELS = {
    DEBUG: 0,
    INFO: 1,
    SUCCESS: 2,
    WARNING: 3,
    ERROR: 4,
    SILENT: 5,
};

/**
 * Current log level (default: INFO)
 */
let currentLevel = LOG_LEVELS.INFO;

/**
 * Whether a message at the given level should be emitted (respects current log level).
 * @param {number} level - Level from LOG_LEVELS
 * @returns {boolean}
 * @private
 */
function canLog(level) {
    return currentLevel <= level;
}

/**
 * Set log level
 * @param {number} level - Log level from LOG_LEVELS
 */
export function setLogLevel(level) {
    currentLevel = level;
}

/**
 * Get current log level
 * @returns {number}
 */
export function getLogLevel() {
    return currentLevel;
}

/**
 * Logger object with various methods
 */
const logger = {
    /**
     * Debug message (gray)
     * @param {string} msg - Message to log
     */
    debug: (msg) => {
        if (currentLevel <= LOG_LEVELS.DEBUG) {
            console.log(`${colors.gray}[DEBUG]${colors.reset} ${msg}`);
        }
    },

    /**
     * Info message (cyan)
     * @param {string} msg - Message to log
     */
    info: (msg) => {
        if (currentLevel <= LOG_LEVELS.INFO) {
            console.log(`${colors.cyan}[*]${colors.reset} ${msg}`);
        }
    },

    /**
     * Success message (green)
     * @param {string} msg - Message to log
     */
    success: (msg) => {
        if (currentLevel <= LOG_LEVELS.SUCCESS) {
            console.log(`${colors.green}[+]${colors.reset} ${msg}`);
        }
    },

    /**
     * Warning message (yellow)
     * @param {string} msg - Message to log
     */
    warning: (msg) => {
        if (currentLevel <= LOG_LEVELS.WARNING) {
            console.log(`${colors.yellow}[!]${colors.reset} ${msg}`);
        }
    },

    /**
     * Error message (red)
     * @param {string} msg - Message to log
     */
    error: (msg) => {
        if (currentLevel <= LOG_LEVELS.ERROR) {
            console.error(`${colors.red}[x]${colors.reset} ${msg}`);
        }
    },

    /**
     * Raw output without prefix
     * @param {string} msg - Message to log
     */
    raw: (msg) => {
        if (canLog(LOG_LEVELS.INFO)) {
            console.log(msg);
        }
    },

    /**
     * Separator line
     * @param {string} char - Character to use
     * @param {number} length - Line length
     */
    separator: (char = '─', length = 60) => {
        if (canLog(LOG_LEVELS.INFO)) {
            console.log(colors.gray + char.repeat(length) + colors.reset);
        }
    },

    /**
     * Highlighted title
     * @param {string} msg - Title text
     */
    title: (msg) => {
        if (canLog(LOG_LEVELS.INFO)) {
            console.log(`${colors.cyan}${colors.bold}${msg}${colors.reset}`);
        }
    },

    /**
     * Step indicator for exploit flow
     * @param {number} step - Step number
     * @param {string} msg - Step description
     */
    step: (step, msg) => {
        if (canLog(LOG_LEVELS.INFO)) {
            console.log(`${colors.magenta}[${step}]${colors.reset} ${msg}`);
        }
    },

    /**
     * Request indicator
     * @param {string} method - HTTP method
     * @param {string} url - Request URL
     */
    request: (method, url) => {
        if (canLog(LOG_LEVELS.INFO)) {
            console.log(`${colors.yellow}[>]${colors.reset} ${method} ${url}`);
        }
    },

    /**
     * Response indicator
     * @param {number} status - HTTP status code
     * @param {string} text - Status text
     */
    response: (status, text = '') => {
        const color = status < 400 ? colors.green : colors.red;
        if (canLog(LOG_LEVELS.INFO)) {
            console.log(`${colors.green}[<]${colors.reset} ${color}${status}${colors.reset} ${text}`);
        }
    },

    /**
     * Found indicator (for extracted data)
     * @param {string} label - What was found
     * @param {string} value - The value found
     */
    found: (label, value) => {
        if (canLog(LOG_LEVELS.INFO)) {
            console.log(`${colors.green}[✓]${colors.reset} ${label}: ${colors.cyan}${value}${colors.reset}`);
        }
    },

    /**
     * Box around text for emphasis
     * @param {string} text - Text to box
     * @param {string} color - Box color
     */
    box: (text, color = 'cyan') => {
        if (canLog(LOG_LEVELS.INFO)) {
            const c = colors[color] || colors.cyan;
            const width = text.length + 4;
            console.log(`${c}╔${'═'.repeat(width)}╗${colors.reset}`);
            console.log(`${c}║${colors.reset}  ${text}  ${c}║${colors.reset}`);
            console.log(`${c}╚${'═'.repeat(width)}╝${colors.reset}`);
        }
    },
};

export default logger;

