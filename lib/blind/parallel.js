/**
 * Parallel blind extraction (Component E)
 *
 * Extracts an unknown string character-by-character through a user-supplied
 * oracle — the classic engine behind blind SQL injection and similar side
 * channels. Serial extraction is slow; this parallelizes the work *by position*
 * using a Promise pool (Node's equivalent of a thread pool) with a hard
 * concurrency limit, so it stays viable within an engagement's time budget
 * without exhausting the target or your sockets.
 *
 * The library owns the plumbing — the per-position loop, the parallelization,
 * the assembly of the result. The oracle (the function that performs the
 * injection and decides the outcome) is ALWAYS supplied by the caller and is
 * never embedded in the library.
 *
 * One extraction machine drives all four modes (linear/binary × boolean/time);
 * only how the oracle decides each step changes.
 *
 * For authorized security testing and educational use only. Only run this
 * against systems you own or have explicit written permission to test.
 */

import { colors } from '../utils/colors.js';
import logger from '../utils/logger.js';
import { ValidationError, ExploitError } from '../utils/errors.js';

/**
 * Build the default charset: printable ASCII (32..126).
 * @returns {string}
 * @private
 */
function defaultCharset() {
    let s = '';
    for (let c = 32; c <= 126; c++) s += String.fromCharCode(c);
    return s;
}

/**
 * A simple counting semaphore to cap the number of in-flight oracle calls.
 * @param {number} max - Maximum concurrent holders
 * @returns {{ acquire: () => Promise<void>, release: () => void }}
 * @private
 */
function createSemaphore(max) {
    let active = 0;
    const queue = [];
    const acquire = () => new Promise((resolve) => {
        if (active < max) {
            active++;
            resolve();
        } else {
            queue.push(resolve);
        }
    });
    const release = () => {
        active--;
        const next = queue.shift();
        if (next) {
            active++;
            next();
        }
    };
    return { acquire, release };
}

/**
 * Wrap a raw async oracle with (a) the concurrency semaphore and (b) retry on
 * error, so a single flaky network call never aborts a whole position (RE-6).
 * @param {Function} fn - Raw async oracle
 * @param {object} sem - Semaphore
 * @param {number} retries - Extra attempts after the first
 * @returns {(...args: any[]) => Promise<any>}
 * @private
 */
function guard(fn, sem, retries) {
    return async (...args) => {
        let lastErr;
        for (let attempt = 0; attempt <= retries; attempt++) {
            await sem.acquire();
            try {
                return await fn(...args);
            } catch (err) {
                lastErr = err;
                logger.warning(`oracle error (attempt ${attempt + 1}/${retries + 1}): ${err.message}`);
            } finally {
                sem.release();
            }
        }
        throw new ExploitError(
            `Oracle failed after ${retries + 1} attempts: ${lastErr ? lastErr.message : 'unknown error'}`,
            'extractBlind',
            lastErr
        );
    };
}

/**
 * Linear scan: test each charset character at a position via an equality
 * decision. Returns the matching character, or null when nothing matches —
 * which doubles as the end-of-string terminator during length discovery (RE-4).
 * @param {number} position - 1-based position (as passed to the oracle)
 * @param {(pos: number, guess: string) => Promise<boolean>} decide - Equality decision
 * @param {string} charset - Characters to try
 * @returns {Promise<string|null>}
 * @private
 */
async function linearScanChar(position, decide, charset) {
    for (const ch of charset) {
        if (await decide(position, ch)) return ch;
    }
    return null;
}

/**
 * Binary search: locate a position's character with a greater-than comparison
 * decision, in O(log n) calls instead of O(n) (RE-8). Assumes `sorted` is the
 * charset in ascending order and the actual character is within it.
 * @param {number} position - 1-based position
 * @param {(pos: number, guess: string) => Promise<boolean>} decide - "char at pos > guess?"
 * @param {string[]} sorted - Charset sorted ascending
 * @returns {Promise<string>}
 * @private
 */
async function binarySearchChar(position, decide, sorted) {
    let lo = 0;
    let hi = sorted.length - 1;
    while (lo < hi) {
        const mid = (lo + hi) >> 1;
        // decide === true  → actual char is greater than sorted[mid]
        if (await decide(position, sorted[mid])) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return sorted[lo];
}

/**
 * Discover the string length using a length oracle `lengthOracle(n) => length >= n`.
 * Exponential search for an upper bound, then binary search — O(log n) calls.
 * @param {(n: number) => Promise<boolean>} lengthOracle - "is length >= n?"
 * @param {number} maxLength - Safety cap
 * @returns {Promise<number>}
 * @private
 */
async function discoverLengthViaOracle(lengthOracle, maxLength) {
    if (!(await lengthOracle(1))) return 0;
    let hi = 1;
    while (hi <= maxLength && (await lengthOracle(hi))) hi *= 2;
    let lo = Math.floor(hi / 2);
    hi = Math.min(hi, maxLength);
    // Largest n for which lengthOracle(n) is true.
    while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2);
        if (await lengthOracle(mid)) lo = mid;
        else hi = mid - 1;
    }
    return lo;
}

/**
 * Extract a blind value character-by-character, parallelizing by position.
 *
 * The engine is oracle-driven and identical across the four modes; the caller
 * supplies the oracle that matches the chosen strategy/mode:
 *
 * - `strategy: 'linear'` — oracle answers **equality**: `oracle(position, guess)`
 *   returns true when the character at `position` equals `guess`.
 * - `strategy: 'binary'` — oracle answers **greater-than**: `oracle(position, guess)`
 *   returns true when the character at `position` is greater than `guess`
 *   (O(log n) calls per character).
 * - `mode: 'boolean'` — the oracle returns the boolean directly.
 * - `mode: 'time'` — the oracle induces a delay when the condition holds;
 *   `timeOracle(position, guess)` returns the response time in ms and the engine
 *   classifies it against `delayThreshold`. If only `oracle` is given in time
 *   mode, its wall-clock time is measured instead.
 *
 * Positions are 1-based when passed to the oracle (matching SQL `SUBSTRING`).
 *
 * @param {object} options - Options
 * @param {(position: number, guess: string) => Promise<boolean>} [options.oracle] - Boolean-mode oracle
 * @param {(position: number, guess: string) => Promise<number>} [options.timeOracle] - Time-mode oracle (returns ms)
 * @param {(n: number) => Promise<boolean>} [options.lengthOracle] - Optional "length >= n?" oracle for length discovery
 * @param {number} [options.length] - Known length; omit for auto-discovery
 * @param {string} [options.charset] - Candidate characters (default: printable ASCII 32..126)
 * @param {number} [options.concurrency=20] - Max concurrent oracle calls
 * @param {'linear'|'binary'} [options.strategy='linear'] - Search strategy
 * @param {'boolean'|'time'} [options.mode='boolean'] - Oracle decision type
 * @param {number} [options.delayThreshold=1000] - ms threshold classifying true/false in time mode
 * @param {number} [options.retries=3] - Retry attempts per oracle call on error
 * @param {number} [options.maxLength=256] - Safety cap for length auto-discovery
 * @param {(partial: string) => void} [options.onProgress] - Called with the growing known prefix
 * @returns {Promise<string>} - The reconstructed value
 * @throws {ValidationError} On invalid options
 * @throws {ExploitError} When the oracle fails irrecoverably
 */
export async function extractBlind(options = {}) {
    const {
        oracle,
        timeOracle,
        lengthOracle,
        length,
        charset = defaultCharset(),
        concurrency = 20,
        strategy = 'linear',
        mode = 'boolean',
        delayThreshold = 1000,
        retries = 3,
        maxLength = 256,
        onProgress,
    } = options;

    // ── Validation ──────────────────────────────────────────────
    if (strategy !== 'linear' && strategy !== 'binary') {
        throw new ValidationError(`Unknown strategy: ${strategy}`, 'strategy');
    }
    if (mode !== 'boolean' && mode !== 'time') {
        throw new ValidationError(`Unknown mode: ${mode}`, 'mode');
    }
    if (mode === 'boolean' && typeof oracle !== 'function') {
        throw new ValidationError('boolean mode requires an `oracle` function', 'oracle');
    }
    if (mode === 'time' && typeof timeOracle !== 'function' && typeof oracle !== 'function') {
        throw new ValidationError('time mode requires a `timeOracle` (or `oracle`) function', 'timeOracle');
    }
    if (!charset || charset.length === 0) {
        throw new ValidationError('charset must be a non-empty string', 'charset');
    }
    if (concurrency < 1) {
        throw new ValidationError('concurrency must be >= 1', 'concurrency');
    }

    const sem = createSemaphore(concurrency);

    // ── Build the single boolean decision function ──────────────
    // The extraction machine only ever calls decide(position, guess) → boolean.
    let rawDecide;
    if (mode === 'time') {
        if (typeof timeOracle === 'function') {
            rawDecide = async (pos, guess) => (await timeOracle(pos, guess)) >= delayThreshold;
        } else {
            // Measure the plain oracle's wall-clock time.
            rawDecide = async (pos, guess) => {
                const t0 = Date.now();
                await oracle(pos, guess);
                return (Date.now() - t0) >= delayThreshold;
            };
        }
    } else {
        rawDecide = (pos, guess) => oracle(pos, guess);
    }
    const decide = guard(rawDecide, sem, retries);

    const sortedCharset = strategy === 'binary'
        ? [...charset].sort((a, b) => a.charCodeAt(0) - b.charCodeAt(0))
        : null;

    // Per-position extraction: one char or null (null only in linear scans).
    const extractPosition = (position) =>
        strategy === 'binary'
            ? binarySearchChar(position, decide, sortedCharset)
            : linearScanChar(position, decide, charset);

    // ── Progress reporting (char-by-char, [=]/[+] style) ────────
    let lastReported = 0;
    const report = (partial) => {
        if (partial.length > lastReported) {
            lastReported = partial.length;
            logger.raw(`${colors.cyan}[=]${colors.reset} ${partial}`);
            if (typeof onProgress === 'function') onProgress(partial);
        }
    };

    // ── Determine length ────────────────────────────────────────
    let knownLength = length;
    if (knownLength == null) {
        if (typeof lengthOracle === 'function') {
            const guardedLen = guard(lengthOracle, sem, retries);
            knownLength = await discoverLengthViaOracle(guardedLen, maxLength);
            logger.info(`Discovered length: ${knownLength}`);
        } else if (strategy === 'linear') {
            // No length and no length oracle → use the no-match terminator,
            // extracting in parallel batches until a position yields no match.
            const result = await extractUnknownLengthLinear(extractPosition, concurrency, maxLength, report);
            logger.success(`Extracted (${result.length} chars): ${result}`);
            return result;
        } else {
            throw new ValidationError(
                'binary strategy needs `length` or `lengthOracle` when length is unknown',
                'length'
            );
        }
    }

    if (knownLength === 0) {
        logger.success('Extracted (0 chars): (empty)');
        return '';
    }

    // ── Known length: extract every position in parallel ────────
    const results = new Array(knownLength).fill(null);
    const advanceProgress = () => {
        let prefix = '';
        for (let i = 0; i < knownLength; i++) {
            if (results[i] == null) break;
            prefix += results[i];
        }
        report(prefix);
    };

    const tasks = [];
    for (let i = 0; i < knownLength; i++) {
        const position = i + 1; // 1-based for the oracle
        tasks.push((async () => {
            const ch = await extractPosition(position);
            results[i] = ch == null ? '?' : ch;
            advanceProgress();
        })());
    }
    await Promise.all(tasks);

    const result = results.join('');
    logger.success(`Extracted (${result.length} chars): ${result}`);
    return result;
}

/**
 * Unknown-length linear extraction: pull positions in parallel batches and stop
 * at the first position that returns no match (the end-of-string terminator).
 * @param {(position: number) => Promise<string|null>} extractPosition - Per-position extractor
 * @param {number} concurrency - Batch size / parallel width
 * @param {number} maxLength - Safety cap
 * @param {(partial: string) => void} report - Progress reporter
 * @returns {Promise<string>}
 * @private
 */
async function extractUnknownLengthLinear(extractPosition, concurrency, maxLength, report) {
    const chars = [];
    let start = 0;
    const batch = Math.max(1, concurrency);

    while (start < maxLength) {
        const positions = [];
        for (let i = 0; i < batch; i++) positions.push(start + i + 1); // 1-based
        const batchResults = await Promise.all(positions.map((p) => extractPosition(p)));

        let ended = false;
        for (const ch of batchResults) {
            if (ch == null) { ended = true; break; }
            chars.push(ch);
            report(chars.join(''));
        }
        if (ended) break;
        start += batch;
    }

    return chars.join('');
}
