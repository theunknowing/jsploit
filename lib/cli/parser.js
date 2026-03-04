/**
 * CLI Argument Parser
 *
 * Parses process.argv into params object (with defaults from options), list of errors for unknown/missing values,
 * and positionals. Positionals are mapped to params.command and params.exploitName.
 */
import { options, getOptionByFlag } from './options.js';

/**
 * Parse command-line arguments. Flags are applied to params; unknown or invalid usage is pushed to errors.
 * @param {string[]} argv - Process arguments (process.argv)
 * @returns {{ params: object, errors: string[], positionals: string[] }}
 */
export function parseArgs(argv) {
    // Skip node and script path
    const args = argv.slice(2);
    const params = {};
    const errors = [];
    const positionals = [];

    // Initialize defaults
    for (const [key, def] of Object.entries(options)) {
        if (def.type !== 'positional') {
            params[key] = def.default;
        }
    }

    let i = 0;
    while (i < args.length) {
        const arg = args[i];

        // Check if it's a flag
        if (arg.startsWith('-')) {
            const option = getOptionByFlag(arg);

            if (!option) {
                errors.push(`Unknown option: ${arg}`);
                i++;
                continue;
            }

            // Handle different types
            switch (option.type) {
                case 'boolean':
                    params[option.key] = true;
                    break;

                case 'string':
                    if (i + 1 >= args.length || args[i + 1].startsWith('-')) {
                        errors.push(`Option ${arg} requires a value`);
                    } else {
                        i++;
                        params[option.key] = args[i];
                    }
                    break;

                case 'number':
                    if (i + 1 >= args.length || args[i + 1].startsWith('-')) {
                        errors.push(`Option ${arg} requires a numeric value`);
                    } else {
                        i++;
                        const num = parseInt(args[i]);
                        if (isNaN(num)) {
                            errors.push(`Option ${arg} requires a numeric value, got: ${args[i]}`);
                        } else {
                            params[option.key] = num;
                        }
                    }
                    break;

                case 'array':
                    if (i + 1 >= args.length || args[i + 1].startsWith('-')) {
                        errors.push(`Option ${arg} requires a value`);
                    } else {
                        i++;
                        if (!Array.isArray(params[option.key])) {
                            params[option.key] = [];
                        }
                        params[option.key].push(args[i]);
                    }
                    break;
            }
        } else {
            // It's a positional argument
            positionals.push(arg);
        }

        i++;
    }

    // Map positionals to named params
    if (positionals.length > 0) {
        params.command = positionals[0];
    }
    if (positionals.length > 1) {
        params.exploitName = positionals[1];
    }

    return { params, errors, positionals };
}

/**
 * Validate command-specific required params (e.g. exploit name for new/run). Returns array of error messages.
 * @param {object} params - Parsed parameters
 * @param {string} command - Command being run (new, run, list)
 * @returns {string[]} - Validation error messages (empty if valid)
 */
export function validateParams(params, command) {
    const errors = [];

    switch (command) {
        case 'new':
            if (!params.exploitName) {
                errors.push('Exploit name is required for "new" command');
            }
            break;

        case 'run':
            if (!params.exploitName) {
                errors.push('Exploit name/path is required for "run" command');
            }
            break;

        case 'list':
            // No additional validation needed
            break;

        default:
            if (command && command !== '') {
                errors.push(`Unknown command: ${command}. Use: new, run, list`);
            }
            break;
    }

    return errors;
}

