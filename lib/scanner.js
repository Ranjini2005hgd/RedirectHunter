'use strict';

const { PATH_PAYLOADS, PARAM_PAYLOADS, COMMON_PARAMS, fill } = require('./payloads');

/** Is `hostname` the canary domain or one of its subdomains? */
function isCanaryHost(hostname, canary) {
  const h = (hostname || '').toLowerCase().replace(/\.$/, '');
  const c = canary.toLowerCase();
  return h === c || h.endsWith('.' + c);
}

/** Resolve a Location value the way a browser would (backslashes act as slashes). */
function resolveLocation(location, base) {
  try {
    const cleaned = location.trim().replace(/\\/g, '/');
    return new URL(cleaned, base);
  } catch {
    return null;
  }
}

/** Build the list of test cases for one target URL. */
function buildTests(rawUrl, opts) {
  const u = new URL(rawUrl);
  const ctx = { domain: opts.domain, host: u.hostname };
  const tests = [];
  const seen = new Set();
  const add = (url, payload, kind, param) => {
    if (seen.has(url)) return;
    seen.add(url);
    tests.push({ url, payload, kind, param });
  };

  if (opts.mode === 'path' || opts.mode === 'both') {
    const base = rawUrl.replace(/\/+$/, '');
    for (const tpl of PATH_PAYLOADS) {
      const p = fill(tpl, ctx);
      add(base + p, p, 'path');
    }
  }

  if (opts.mode === 'param' || opts.mode === 'both') {
    const names = new Set(u.searchParams.keys());
    if (opts.commonParams) COMMON_PARAMS.forEach((n) => names.add(n));
    for (const name of names) {
      for (const tpl of PARAM_PAYLOADS) {
        const p = fill(tpl, ctx);
        const t = new URL(rawUrl);
        t.searchParams.set(name, p);
        add(t.toString(), p, 'param', name);
      }
    }
  }
  return tests;
}

/** Look for client-side redirects in an HTML body. */
function findClientRedirect(body, base, canary) {
  const patterns = [
    /<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["'][^"']*url=([^"'>\s]+)/i,
    /(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/i,
    /location\.(?:replace|assign)\(\s*["']([^"']+)["']\s*\)/i
  ];
  for (const re of patterns) {
    const m = body.match(re);
    if (m) {
      const r = resolveLocation(m[1], base);
      if (r && isCanaryHost(r.hostname, canary)) return { to: r.toString() };
    }
  }
  return null;
}

/**
 * Request a single test URL, following same-site redirects manually so that we
 * never actually connect to the canary domain.
 * Returns a finding object or null.
 */
async function probe(test, opts) {
  let current = test.url;
  const chain = [];

  for (let hop = 0; hop <= opts.maxRedirects; hop++) {
    let res;
    try {
      res = await fetch(current, {
        method: 'GET',
        redirect: 'manual',
        headers: { 'User-Agent': opts.userAgent, Accept: '*/*', ...opts.headers },
        signal: AbortSignal.timeout(opts.timeout)
      });
    } catch (err) {
      return { error: err.cause?.code || err.name || err.message };
    }

    const location = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && location) {
      const target = resolveLocation(location, current);
      chain.push(`${res.status} ${location}`);
      if (!target) return null;
      if (isCanaryHost(target.hostname, opts.domain)) {
        return {
          type: 'server-side',
          status: res.status,
          location,
          chain
        };
      }
      if (!/^https?:$/.test(target.protocol)) return null;
      current = target.toString();
      await res.body?.cancel().catch(() => {});
      continue;
    }

    // Not a redirect: check for client-side redirect to the canary
    if (opts.clientSide && res.status === 200) {
      const ct = res.headers.get('content-type') || '';
      if (/html|javascript/i.test(ct)) {
        const body = (await res.text()).slice(0, 200000);
        const cs = findClientRedirect(body, current, opts.domain);
        if (cs) return { type: 'client-side', status: res.status, location: cs.to, chain };
      }
    }
    await res.body?.cancel().catch(() => {});
    return null;
  }
  return null;
}

module.exports = { buildTests, probe, isCanaryHost, resolveLocation, findClientRedirect };
