/**
 * CLI Option Definitions
 *
 * Defines all available command-line options for jsploit. Each entry has: flags (e.g. ['-t', '--target']),
 * description, default, type ('string'|'number'|'boolean'|'positional'|'array'), and category for help grouping.
 */
export const options = {
    // ─────────────────────────────────────────────────────────────
    // COMMANDS
    // ─────────────────────────────────────────────────────────────
    command: {
        flags: [],
        description: 'Command to run (new, run, list)',
        default: '',
        type: 'positional',
        category: 'commands',
    },

    exploitName: {
        flags: [],
        description: 'Exploit name or path',
        default: '',
        type: 'positional',
        category: 'commands',
    },

    // ─────────────────────────────────────────────────────────────
    // OPTIONS
    // ─────────────────────────────────────────────────────────────
    target: {
        flags: ['-t', '--target'],
        description: 'Target URL for the exploit',
        default: '',
        type: 'string',
        category: 'options',
    },

    dir: {
        flags: ['--dir'],
        description: 'Exploit directory (default: ./exploits)',
        default: '',
        type: 'string',
        category: 'options',
    },

    proxy: {
        flags: ['-x', '--proxy'],
        description: 'Proxy to use (host:port)',
        default: '',
        type: 'string',
        category: 'options',
    },

    timeout: {
        flags: ['--timeout'],
        description: 'Request timeout in ms',
        default: 30000,
        type: 'number',
        category: 'options',
    },

    verify: {
        flags: ['--verify'],
        description: 'Verify SSL certificates',
        default: false,
        type: 'boolean',
        category: 'options',
    },

    verbose: {
        flags: ['-v', '--verbose'],
        description: 'Verbose output',
        default: false,
        type: 'boolean',
        category: 'options',
    },

    debug: {
        flags: ['-d', '--debug'],
        description: 'Debug mode (show stack traces)',
        default: false,
        type: 'boolean',
        category: 'options',
    },

    // ─────────────────────────────────────────────────────────────
    // OUTPUT
    // ─────────────────────────────────────────────────────────────
    output: {
        flags: ['-o', '--output'],
        description: 'Output file for results',
        default: '',
        type: 'string',
        category: 'output',
    },

    silent: {
        flags: ['-s', '--silent'],
        description: 'Suppress all output except results',
        default: false,
        type: 'boolean',
        category: 'output',
    },

    noColor: {
        flags: ['--no-color'],
        description: 'Disable colored output',
        default: false,
        type: 'boolean',
        category: 'output',
    },

    // ─────────────────────────────────────────────────────────────
    // INFO
    // ─────────────────────────────────────────────────────────────
    help: {
        flags: ['-h', '--help'],
        description: 'Show help message',
        default: false,
        type: 'boolean',
        category: 'info',
    },

    version: {
        flags: ['-V', '--version'],
        description: 'Show version number',
        default: false,
        type: 'boolean',
        category: 'info',
    },
};

/**
 * Get option by flag
 * @param {string} flag - Flag to search
 * @returns {object|null}
 */
export function getOptionByFlag(flag) {
    for (const [key, def] of Object.entries(options)) {
        if (def.flags && def.flags.includes(flag)) {
            return { key, ...def };
        }
    }
    return null;
}

/**
 * Get all flags
 * @returns {string[]}
 */
export function getAllFlags() {
    const flags = [];
    for (const def of Object.values(options)) {
        if (def.flags) {
            flags.push(...def.flags);
        }
    }
    return flags;
}

