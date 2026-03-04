#!/usr/bin/env node

/**
 * jsploit - Exploit Development Framework
 * CLI Entry Point
 * 
 * A exploit development framework with:
 * - Session management (like Python requests)
 * - Automatic cookie handling
 * - HTML parsing utilities
 * - SSL bypass
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { parseArgs, validateParams } from '../lib/cli/parser.js';
import { generateHelp, getVersion } from '../lib/cli/help.js';
import { disableColors, colors } from '../lib/utils/colors.js';
import logger, { setLogLevel, LOG_LEVELS } from '../lib/utils/logger.js';
import {
    EXIT_CODES,
    ValidationError,
    ConnectionError,
    TimeoutError,
    HttpError,
    ParseError,
    ExploitError,
} from '../lib/utils/errors.js';

// Get directory paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PACKAGE_ROOT_DIR = path.resolve(__dirname, '..');
const PACKAGE_TEMPLATE_PATH = path.join(PACKAGE_ROOT_DIR, 'exploits', 'template.js');

/**
 * Resolve the directory where exploits are stored. Default is ./exploits relative to process.cwd().
 * Use --dir to override (absolute path or relative to cwd).
 * @param {object} [params] - CLI params (params.dir)
 * @returns {string} - Absolute path to exploits directory
 */
function resolveExploitDir(params) {
    const raw = params?.dir && String(params.dir).trim() ? String(params.dir).trim() : '';
    if (!raw) return path.join(process.cwd(), 'exploits');
    return path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);
}

/**
 * Resolve path to template.js: prefer local template inside exploitsDir, then package template.
 * @param {string} exploitsDir - Exploits directory path
 * @returns {string|null} - Path to template.js or null if none found
 */
function resolveTemplatePath(exploitsDir) {
    const localTemplate = path.join(exploitsDir, 'template.js');
    if (fs.existsSync(localTemplate)) return localTemplate;
    if (fs.existsSync(PACKAGE_TEMPLATE_PATH)) return PACKAGE_TEMPLATE_PATH;
    return null;
}

/**
 * Create a new exploit file from template in the exploits directory (see resolveExploitDir).
 * Replaces EXPLOIT_NAME and EXPLOIT_DATE in template. Suggests npm i jsploit if not installed locally.
 * @param {string} name - Exploit name (sanitized to safe filename)
 * @param {object} params - CLI parameters (e.g. params.dir)
 * @returns {Promise<number>} - EXIT_CODES.SUCCESS or VALIDATION_ERROR
 */
async function createExploit(name, params) {
    const exploitsDir = resolveExploitDir(params);

    // Sanitize name
    const safeName = name.replace(/[^a-zA-Z0-9_-]/g, '-');
    const fileName = safeName.endsWith('.js') ? safeName : `${safeName}.js`;
    const filePath = path.join(exploitsDir, fileName);

    // Check if exists
    if (fs.existsSync(filePath)) {
        logger.error(`Exploit already exists: ${fileName}`);
        logger.info(`Use a different name or delete the existing file.`);
        return EXIT_CODES.VALIDATION_ERROR;
    }

    // Ensure exploits directory exists
    if (!fs.existsSync(exploitsDir)) {
        fs.mkdirSync(exploitsDir, { recursive: true });
    }

    // Read template
    let template;
    const templatePath = resolveTemplatePath(exploitsDir);
    if (templatePath) {
        template = fs.readFileSync(templatePath, 'utf8');
    } else {
        template = generateDefaultTemplate(safeName);
    }

    // Replace placeholders
    const content = template
        .replace(/EXPLOIT_NAME/g, safeName)
        .replace(/EXPLOIT_DATE/g, new Date().toISOString().split('T')[0]);

    // Write exploit file
    fs.writeFileSync(filePath, content);

    logger.success(`Created exploit: ${colors.cyan}${fileName}${colors.reset}`);
    logger.info(`Edit: ${colors.gray}${filePath}${colors.reset}`);
    logger.info(`Run:  ${colors.gray}jsploit run ${safeName} -t http://target.com${colors.reset}`);
    if (!fs.existsSync(path.join(process.cwd(), 'node_modules', 'jsploit', 'package.json'))) {
        logger.info(`Tip: install jsploit locally: ${colors.cyan}npm i jsploit${colors.reset}`);
    }

    return EXIT_CODES.SUCCESS;
}

/**
 * Generate default template if template.js doesn't exist
 * @param {string} name - Exploit name
 * @returns {string}
 */
function generateDefaultTemplate(name) {
    return `/**
 * Exploit: ${name}
 * Created: ${new Date().toISOString().split('T')[0]}
 * 
 * Description:
 *   [Add exploit description here]
 */

import { Session, parse, logger } from 'jsploit';

/**
 * Exploit configuration
 */
export const metadata = {
    name: '${name}',
    description: 'Exploit description',
    author: 'anonymous',
    version: '1.0.0',
    target: '',
};

/**
 * Main exploit function
 * @param {object} options - Runtime options
 * @param {string} options.target - Target URL
 * @param {object} options.proxy - Proxy configuration
 * @param {boolean} options.verbose - Verbose mode
 */
export async function exploit(options = {}) {
    const { target, proxy, verbose, timeout = 30000, verify = false } = options;

    if (!target) {
        throw new Error('Target URL is required (-t)');
    }

    logger.title('Starting exploit: ${name}');
    logger.separator();

    // Create session
    const session = new Session({
        baseUrl: target,
        verify,
        timeout,
        proxy,
    });

    // Step 1: Reconnaissance
    logger.step(1, 'Fetching target...');
    const res = await session.get('/');

    if (!res.ok) {
        logger.error(\`Failed to reach target: \${res.status}\`);
        return { success: false, error: 'Target unreachable' };
    }

    logger.response(res.status, res.statusText);

    // Step 2: Parse response
    logger.step(2, 'Parsing response...');
    const html = parse(res.body);

    // Look for forms
    const form = html.getForm(0);
    if (form) {
        logger.found('Form', form.action || '(default)');
        logger.info(\`Method: \${form.method}\`);
    }

    // Look for CSRF token
    const csrf = html.findCSRFToken();
    if (csrf) {
        logger.found('CSRF Token', csrf.value);
    }

    // Step 3: Exploit logic
    logger.step(3, 'Executing exploit...');
    
    // TODO: Add exploit logic here

    logger.separator();
    logger.success('Exploit completed');

    return {
        success: true,
        data: {
            // Add extracted data here
        },
    };
}

// Run if executed directly
if (import.meta.url === \`file://\${process.argv[1]}\`) {
    const target = process.argv[2] || process.env.TARGET;
    exploit({ target }).catch(console.error);
}
`;
}

/**
 * Load and run an exploit module. Resolves name to path: absolute path, relative path, or name in exploits dir.
 * Imports via file:// URL; passes target, proxy, verbose, debug, timeout, verify to exploit().
 * Writes result to params.output if set; in silent mode prints only JSON result.
 * @param {string} name - Exploit name (e.g. my-exploit) or path (absolute or relative)
 * @param {object} params - CLI parameters (target, proxy, verbose, output, silent, dir, etc.)
 * @returns {Promise<number>} - EXIT_CODES value
 */
async function runExploit(name, params) {
    const exploitsDir = resolveExploitDir(params);

    // Resolve exploit path
    let exploitPath;

    if (path.isAbsolute(name)) {
        exploitPath = name;
    } else if (name.includes('/') || name.includes('\\')) {
        exploitPath = path.resolve(process.cwd(), name);
    } else {
        // Look in exploits directory
        const fileName = name.endsWith('.js') ? name : `${name}.js`;
        exploitPath = path.join(exploitsDir, fileName);
    }

    // Check if exists
    if (!fs.existsSync(exploitPath)) {
        logger.error(`Exploit not found: ${name}`);
        logger.info(`Create it with: ${colors.cyan}jsploit new ${name}${colors.reset}`);
        return EXIT_CODES.VALIDATION_ERROR;
    }

    // Import and run exploit
    try {
        if (params.verbose) {
            logger.info(`Loading: ${exploitPath}`);
        }

        const moduleUrl = `${pathToFileURL(exploitPath).href}?t=${Date.now()}`;
        let module;
        try {
            module = await import(moduleUrl);
        } catch (err) {
            const msg = String(err?.message || err);
            if (err?.code === 'ERR_MODULE_NOT_FOUND' || msg.includes("Cannot find package 'jsploit'")) {
                logger.error('Missing dependency: jsploit is not installed in this directory.');
                logger.info(`Run: ${colors.cyan}npm i jsploit${colors.reset} (or run via a project with jsploit installed)`);
                return EXIT_CODES.VALIDATION_ERROR;
            }
            throw err;
        }

        if (typeof module.exploit !== 'function') {
            logger.error('Exploit must export an "exploit" function');
            return EXIT_CODES.VALIDATION_ERROR;
        }

        // Show metadata if available
        if (module.metadata && !params.silent) {
            logger.box(`${module.metadata.name || name} v${module.metadata.version || '1.0.0'}`);
            if (module.metadata.description) {
                logger.info(module.metadata.description);
            }
        }

        // Parse proxy
        let proxy = null;
        if (params.proxy) {
            const [host, port] = params.proxy.split(':');
            proxy = { host, port: parseInt(port) || 8080 };
        }

        // Run exploit
        const result = await module.exploit({
            target: params.target,
            proxy,
            verbose: params.verbose,
            debug: params.debug,
            timeout: params.timeout,
            verify: params.verify,
        });

        // Persist results if requested
        if (params.output) {
            const outPath = path.isAbsolute(params.output)
                ? params.output
                : path.resolve(process.cwd(), params.output);
            const outDir = path.dirname(outPath);
            if (outDir && !fs.existsSync(outDir)) {
                fs.mkdirSync(outDir, { recursive: true });
            }
            fs.writeFileSync(outPath, JSON.stringify(result ?? {}, null, 2));
        }

        // Silent mode: print only results as JSON
        if (params.silent) {
            console.log(JSON.stringify(result ?? {}, null, 2));
            if (result && result.success) return EXIT_CODES.SUCCESS;
            if (result && result.error) return EXIT_CODES.EXPLOIT_ERROR;
            return EXIT_CODES.SUCCESS;
        }

        // Handle result
        if (result && result.success) {
            logger.success('Exploit successful!');
            if (result.data && params.verbose) {
                logger.raw(JSON.stringify(result.data, null, 2));
            }
            return EXIT_CODES.SUCCESS;
        } else if (result && result.error) {
            logger.error(`Exploit failed: ${result.error}`);
            return EXIT_CODES.EXPLOIT_ERROR;
        }

        return EXIT_CODES.SUCCESS;

    } catch (err) {
        if (err instanceof ValidationError) {
            logger.error(`Validation: ${err.message}`);
            return EXIT_CODES.VALIDATION_ERROR;
        }

        if (err instanceof ConnectionError) {
            logger.error(`Connection: ${err.message}`);
            return EXIT_CODES.CONNECTION_ERROR;
        }

        if (err instanceof TimeoutError) {
            logger.error(`Timeout: ${err.message}`);
            return EXIT_CODES.TIMEOUT_ERROR;
        }

        if (err instanceof HttpError) {
            logger.error(`HTTP ${err.statusCode}: ${err.message}`);
            return EXIT_CODES.HTTP_ERROR;
        }

        if (err instanceof ParseError) {
            logger.error(`Parse: ${err.message}`);
            return EXIT_CODES.PARSE_ERROR;
        }

        if (err instanceof ExploitError) {
            logger.error(`Exploit: ${err.message}`);
            if (err.step) {
                logger.info(`Failed at step: ${err.step}`);
            }
            return EXIT_CODES.EXPLOIT_ERROR;
        }

        // Unknown error
        logger.error(`Error: ${err.message}`);
        if (params.debug) {
            console.error(err.stack);
        }
        return EXIT_CODES.UNKNOWN_ERROR;
    }
}

/**
 * List exploit files in the exploits directory (excluding template.js). Uses resolveExploitDir(params).
 * Prints name and description from metadata when present.
 * @param {object} params - CLI parameters (e.g. params.dir for custom directory)
 * @returns {Promise<number>} - EXIT_CODES.SUCCESS
 */
async function listExploits(params) {
    const exploitsDir = resolveExploitDir(params);

    // Ensure directory exists
    if (!fs.existsSync(exploitsDir)) {
        logger.info('No exploits directory found.');
        logger.info(`Create one with: ${colors.cyan}jsploit new <name>${colors.reset}`);
        return EXIT_CODES.SUCCESS;
    }

    // List files
    const files = fs.readdirSync(exploitsDir)
        .filter(f => f.endsWith('.js') && f !== 'template.js');

    if (files.length === 0) {
        logger.info('No exploits found.');
        logger.info(`Create one with: ${colors.cyan}jsploit new <name>${colors.reset}`);
        return EXIT_CODES.SUCCESS;
    }

    logger.title('Available Exploits:');
    logger.separator();

    for (const file of files) {
        const name = file.replace('.js', '');

        // Try to read metadata
        try {
            const exploitPath = path.join(exploitsDir, file);
            const content = fs.readFileSync(exploitPath, 'utf8');

            // Extract description from metadata or comment
            const descMatch = content.match(/description:\s*['"]([^'"]+)['"]/);
            const desc = descMatch ? descMatch[1] : '';

            console.log(`  ${colors.green}${name}${colors.reset}${desc ? ` - ${colors.gray}${desc}${colors.reset}` : ''}`);
        } catch {
            console.log(`  ${colors.green}${name}${colors.reset}`);
        }
    }

    logger.separator();
    logger.info(`Total: ${files.length} exploit(s)`);

    return EXIT_CODES.SUCCESS;
}

/**
 * CLI entry: parse argv, handle --help/--version, validate command and params, then dispatch to new/run/list.
 * Sets log level from --silent and --debug; disables colors for --no-color.
 */
async function main() {
    const { params, errors } = parseArgs(process.argv);

    // Disable colors if requested
    if (params.noColor) {
        disableColors();
    }

    // Set log level
    if (params.silent) {
        setLogLevel(LOG_LEVELS.SILENT);
    } else if (params.debug) {
        setLogLevel(LOG_LEVELS.DEBUG);
    }

    // Show version
    if (params.version) {
        console.log(getVersion());
        process.exit(EXIT_CODES.SUCCESS);
    }

    // Show help
    if (params.help || !params.command) {
        console.log(generateHelp());
        process.exit(EXIT_CODES.SUCCESS);
    }

    // Handle parsing errors
    if (errors.length > 0) {
        console.log(`${colors.red}Errors:${colors.reset}`);
        errors.forEach(err => console.log(`  ${colors.red}x${colors.reset} ${err}`));
        console.log(`\nUse ${colors.cyan}jsploit -h${colors.reset} to see available options.`);
        process.exit(EXIT_CODES.VALIDATION_ERROR);
    }

    // Validate command-specific params
    const validationErrors = validateParams(params, params.command);
    if (validationErrors.length > 0) {
        console.log(`${colors.red}Errors:${colors.reset}`);
        validationErrors.forEach(err => console.log(`  ${colors.red}x${colors.reset} ${err}`));
        process.exit(EXIT_CODES.VALIDATION_ERROR);
    }

    // Execute command
    let exitCode;

    switch (params.command) {
        case 'new':
            exitCode = await createExploit(params.exploitName, params);
            break;

        case 'run':
            exitCode = await runExploit(params.exploitName, params);
            break;

        case 'list':
            exitCode = await listExploits(params);
            break;

        default:
            logger.error(`Unknown command: ${params.command}`);
            logger.info('Use: new, run, list');
            exitCode = EXIT_CODES.VALIDATION_ERROR;
    }

    process.exit(exitCode);
}

// Execute
main().catch(err => {
    console.error(`${colors.red}Fatal error:${colors.reset} ${err.message}`);
    process.exit(EXIT_CODES.UNKNOWN_ERROR);
});

