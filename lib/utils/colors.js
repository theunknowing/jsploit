/**
 * Terminal color utilities
 * 
 * ANSI escape codes for terminal colors.
 * Supports color disabling for non-TTY or --no-color flag.
 */

/**
 * ANSI escape codes for terminal output. Use with disableColors() for --no-color or non-TTY.
 * Keys: reset, bold, dim, italic, underline; foreground (red, green, cyan, gray, etc.); background (bgRed, etc.).
 */
export const colors = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    italic: '\x1b[3m',
    underline: '\x1b[4m',
    
    // Foreground colors
    black: '\x1b[30m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    gray: '\x1b[90m',
    
    // Background colors
    bgBlack: '\x1b[40m',
    bgRed: '\x1b[41m',
    bgGreen: '\x1b[42m',
    bgYellow: '\x1b[43m',
    bgBlue: '\x1b[44m',
    bgMagenta: '\x1b[45m',
    bgCyan: '\x1b[46m',
    bgWhite: '\x1b[47m',
};

/**
 * Disable all colors (for --no-color or non-TTY)
 */
export function disableColors() {
    for (const key of Object.keys(colors)) {
        colors[key] = '';
    }
}

/**
 * Check if colors are enabled
 * @returns {boolean}
 */
export function colorsEnabled() {
    return colors.reset !== '';
}

/**
 * Colorize text with a specific color
 * @param {string} text - Text to colorize
 * @param {string} color - Color name (key from colors object)
 * @returns {string}
 */
export function colorize(text, color) {
    if (!colors[color]) return text;
    return `${colors[color]}${text}${colors.reset}`;
}

