/**
 * Help message generation for jsploit CLI. Builds usage, commands, options by category, examples, and exit codes.
 */
import { colors } from '../utils/colors.js';
import { options } from './options.js';
import { createRequire } from 'module';

// Read package.json in ESM
const require = createRequire(import.meta.url);
const pkg = require('../../package.json');

/**
 * Generate help message
 * @returns {string}
 */
export function generateHelp() {
    const c = colors;

    // Group options by category
    const categories = {
        options: { title: 'Options', items: [] },
        output: { title: 'Output', items: [] },
        info: { title: 'Info', items: [] },
    };

    for (const [key, def] of Object.entries(options)) {
        const category = def.category || 'other';
        if (categories[category] && def.flags && def.flags.length > 0) {
            categories[category].items.push({ key, ...def });
        }
    }

    // Generate help text
    let help = `
${c.red}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ${c.bold}jsploit${c.reset}${c.red} - Exploit Development Framework                    ║
║   v${pkg.version}                                                        ║
║                                                               ║
║   ${c.gray}Session • Cookies • HTML Parse • SSL Bypass${c.reset}${c.red}                ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝${c.reset}

${c.yellow}USAGE:${c.reset}
  jsploit <command> [options]

${c.yellow}COMMANDS:${c.reset}
  ${c.green}new <name>${c.reset}        Create a new exploit from template
  ${c.green}run <name>${c.reset}        Run an exploit
  ${c.green}list${c.reset}              List available exploits

${c.yellow}OPTIONS:${c.reset}
`;

    // Add each category
    for (const [catKey, cat] of Object.entries(categories)) {
        if (cat.items.length === 0) continue;

        help += `\n  ${c.cyan}${cat.title}:${c.reset}\n`;

        for (const opt of cat.items) {
            const flags = opt.flags.join(', ');
            const defaultVal = opt.default !== undefined &&
                opt.default !== '' &&
                opt.default !== false &&
                !Array.isArray(opt.default)
                ? ` ${c.gray}[${opt.default}]${c.reset}`
                : '';

            help += `    ${c.green}${flags.padEnd(24)}${c.reset} ${opt.description}${defaultVal}\n`;
        }
    }

    help += `
${c.yellow}EXAMPLES:${c.reset}

  ${c.cyan}# Create a new exploit${c.reset}
  jsploit new sqli-auth-bypass
  ${c.dim}→ Created exploits/sqli-auth-bypass.js${c.reset}

  ${c.cyan}# Run an exploit${c.reset}
  jsploit run sqli-auth-bypass -t http://target.com
  ${c.dim}→ Running exploit against http://target.com${c.reset}

  ${c.cyan}# Run with proxy (Burp Suite)${c.reset}
  jsploit run sqli-auth-bypass -t http://target.com -x 127.0.0.1:8080
  ${c.dim}→ Traffic proxied through Burp${c.reset}

  ${c.cyan}# List available exploits${c.reset}
  jsploit list
  ${c.dim}→ sqli-auth-bypass.js${c.reset}
  ${c.dim}→ csrf-account-takeover.js${c.reset}

  ${c.cyan}# Use a custom exploits directory${c.reset}
  jsploit new my-exploit --dir ./pocs
  jsploit run my-exploit -t http://target.com --dir ./pocs

${c.yellow}PROGRAMMATIC USAGE:${c.reset}

  ${c.gray}// Import the library${c.reset}
  import { Session, parse } from 'jsploit';

  ${c.gray}// Create a session (like requests.Session)${c.reset}
  const session = new Session({
      verify: false,           ${c.gray}// Ignore SSL errors${c.reset}
      followRedirects: true,   ${c.gray}// Auto-follow redirects${c.reset}
  });

  ${c.gray}// Make requests${c.reset}
  const res = await session.get('http://target.com/login');

  ${c.gray}// Parse HTML and extract CSRF token${c.reset}
  const html = parse(res.body);
  const csrf = html.findCSRFToken();

  ${c.gray}// Submit form with extracted token${c.reset}
  const login = await session.post('/login', {
      form: {
          username: 'admin',
          password: "' OR '1'='1",
          csrf_token: csrf.value,
      }
  });

${c.yellow}EXIT CODES:${c.reset}
  0  Success
  1  Validation error
  2  Connection error
  3  HTTP error
  4  Timeout error
  5  Parse error
  6  Exploit error
`;

    return help;
}

/**
 * Get version string
 * @returns {string}
 */
export function getVersion() {
    return `jsploit v${pkg.version}`;
}

