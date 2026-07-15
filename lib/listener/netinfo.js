/**
 * Network info / LHOST discovery
 *
 * Finds the local IPv4 address a victim/target should call back to. On a VPN
 * pentest the payload must reach the operator over the `tun0` (or `tap0`)
 * interface, never `127.0.0.1` — announcing localhost to a remote target is the
 * classic footgun this module exists to avoid.
 *
 * For authorized security testing and educational use only. Only run this
 * against systems you own or have explicit written permission to test.
 */

import os from 'os';
import dgram from 'dgram';
import logger from '../utils/logger.js';
import { ValidationError } from '../utils/errors.js';

/**
 * Whether an address string is a loopback/localhost address.
 * @param {string} addr - IPv4 address or hostname
 * @returns {boolean}
 * @private
 */
function isLoopback(addr) {
    return (
        addr === '127.0.0.1' ||
        addr === 'localhost' ||
        addr === '::1' ||
        (typeof addr === 'string' && addr.startsWith('127.'))
    );
}

/**
 * Warn (footgun guard) if we are about to hand a remote target a loopback LHOST.
 * @param {string} lhost - Chosen LHOST
 * @param {string} [forTarget] - Target host, if known
 * @private
 */
function warnIfLoopback(lhost, forTarget) {
    if (isLoopback(lhost) && forTarget && !isLoopback(forTarget)) {
        logger.warning(
            `LHOST resolved to ${lhost} for remote target ${forTarget} — ` +
            `the target cannot reach your loopback. Check your VPN interface (tun0/tap0).`
        );
    }
}

/**
 * Discover the LHOST by target: open a "connected" UDP socket toward the
 * target's IP and read the local address the OS picked for the outbound route.
 * No packet is sent (connect() only selects a route), so this is safe and does
 * not touch the target. This is the most robust method — it follows the real
 * routing table instead of guessing by interface name.
 * @param {string} forTarget - Target host or IP
 * @returns {string} - Local IPv4 chosen for that route
 * @private
 */
function lhostForTarget(forTarget) {
    const socket = dgram.createSocket('udp4');
    try {
        // Port 1 / arbitrary — connect() on a UDP socket only assigns the route.
        socket.connect(1, forTarget);
        // connect() on udp4 is async in newer Node; bind synchronously via unref
        // fallback is not possible, so read address after a synchronous connect
        // where available. Node assigns the local endpoint synchronously enough
        // that address() is populated once the socket is bound. To be safe we
        // fall back to interface scanning if it isn't.
        const addr = socket.address();
        if (addr && addr.address && !isLoopback(addr.address)) {
            return addr.address;
        }
    } catch {
        // fall through to interface scan
    } finally {
        try { socket.close(); } catch { /* ignore */ }
    }
    return '';
}

/**
 * Discover the LHOST synchronously by target using route selection. Because
 * dgram.connect() may resolve asynchronously, this promise-based variant waits
 * for the socket to be bound before reading the local address.
 * @param {string} forTarget - Target host or IP
 * @returns {Promise<string>} - Local IPv4 chosen for that route ('' if none)
 * @private
 */
function lhostForTargetAsync(forTarget) {
    return new Promise((resolve) => {
        const socket = dgram.createSocket('udp4');
        let settled = false;
        const done = (value) => {
            if (settled) return;
            settled = true;
            try { socket.close(); } catch { /* ignore */ }
            resolve(value);
        };
        socket.on('error', () => done(''));
        try {
            socket.connect(1, forTarget, () => {
                try {
                    const addr = socket.address();
                    done(addr && addr.address && !isLoopback(addr.address) ? addr.address : '');
                } catch {
                    done('');
                }
            });
        } catch {
            done('');
        }
    });
}

/**
 * List non-internal IPv4 addresses, optionally filtered by an interface-name
 * substring (e.g. 'tun' matches 'tun0').
 * @param {string} [ifaceFilter] - Substring to match against interface names
 * @returns {Array<{ iface: string, address: string }>}
 * @private
 */
function listIPv4(ifaceFilter) {
    const result = [];
    const ifaces = os.networkInterfaces();
    for (const [name, addrs] of Object.entries(ifaces)) {
        if (!addrs) continue;
        if (ifaceFilter && !name.includes(ifaceFilter)) continue;
        for (const a of addrs) {
            // Node <18 uses family 'IPv4', >=18 may use the number 4.
            const isV4 = a.family === 'IPv4' || a.family === 4;
            if (isV4 && !a.internal) {
                result.push({ iface: name, address: a.address });
            }
        }
    }
    return result;
}

/**
 * Get the local IPv4 address the target should call back to (LHOST).
 *
 * Resolution order:
 *   1. `forTarget` given → ask the OS which interface routes to that target
 *      (most robust; follows the real routing table).
 *   2. `iface` given → first non-internal IPv4 on an interface whose name
 *      contains that substring (e.g. `{ iface: 'tun' }` → the tun0 address).
 *   3. Neither → first non-internal IPv4 (VPN tun/tap interfaces preferred).
 *
 * Never returns a wrong value silently: if nothing suitable is found it throws
 * a ValidationError, and it warns (footgun guard) before returning a loopback
 * address for a remote target.
 *
 * @param {object} [options] - Options
 * @param {string} [options.iface] - Interface-name substring filter (e.g. 'tun', 'tap', 'eth0')
 * @param {string} [options.forTarget] - Target host/IP; routes via the OS to pick the outbound interface
 * @returns {string} - IPv4 address for the callback (LHOST)
 * @throws {ValidationError} If no suitable address is found
 */
export function getLHOST(options = {}) {
    const { iface, forTarget } = options;

    // 1. Route-based discovery (most robust). Uses the synchronous read first;
    // dgram.connect() populates the local endpoint synchronously on the
    // platforms we target, so this usually succeeds without awaiting.
    if (forTarget) {
        const routed = lhostForTarget(forTarget);
        if (routed) {
            warnIfLoopback(routed, forTarget);
            return routed;
        }
        // If the sync read didn't work, fall through to interface scanning
        // below rather than returning a wrong value.
        logger.debug(`Route-based LHOST for ${forTarget} unavailable; falling back to interface scan`);
    }

    // 2 & 3. Interface scan (optionally filtered by name).
    const candidates = listIPv4(iface);

    if (candidates.length === 0) {
        const where = iface ? ` matching interface '${iface}'` : '';
        throw new ValidationError(
            `No suitable non-internal IPv4 address found${where}. ` +
            `Is your VPN (tun0/tap0) up? Pass { iface } or { forTarget } to disambiguate.`,
            'iface'
        );
    }

    // Prefer VPN interfaces (tun/tap) when no explicit filter was given.
    if (!iface) {
        const vpn = candidates.find(c => c.iface.includes('tun') || c.iface.includes('tap'));
        if (vpn) {
            warnIfLoopback(vpn.address, forTarget);
            return vpn.address;
        }
    }

    const chosen = candidates[0].address;
    warnIfLoopback(chosen, forTarget);
    return chosen;
}

/**
 * Async variant of {@link getLHOST}. Prefer this when route-based discovery
 * (`forTarget`) must wait for the UDP socket to bind on platforms where
 * dgram.connect() resolves asynchronously.
 * @param {object} [options] - Same options as getLHOST
 * @param {string} [options.iface] - Interface-name substring filter
 * @param {string} [options.forTarget] - Target host/IP for route-based discovery
 * @returns {Promise<string>} - IPv4 address for the callback (LHOST)
 * @throws {ValidationError} If no suitable address is found
 */
export async function getLHOSTAsync(options = {}) {
    const { iface, forTarget } = options;

    if (forTarget) {
        const routed = await lhostForTargetAsync(forTarget);
        if (routed) {
            warnIfLoopback(routed, forTarget);
            return routed;
        }
    }

    // Delegate the interface-scan path to the synchronous resolver.
    return getLHOST({ iface, forTarget });
}
