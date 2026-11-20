
'use strict';

const fs = require('fs');
const { parseArgs } = require('util');
const pkg = require('./package.json');
const { buildTests, probe } = require('./lib/scanner');
const { runPool } = require('./lib/pool');
const { Reporter, banner, c } = require('./lib/output');

const HELP = `
Usage: RedirectHunter [options]

Input:
  -u, --url <url>            Target URL to scan
  -l, --list <file>          File with one URL per line

Options:
  -o, --output <file>        Save report (.json => structured JSON)
  -d, --domain <domain>      Canary domain (default: rh-canary.example)
  -m, --mode <mode>          param | path | both (default: both)
  -p, --common-params        Try common redirect parameter names
  -c, --concurrency <n>      Parallel requests (default: 10)
  -t, --timeout <ms>         Request timeout (default: 10000)
  -r, --max-redirects <n>    Same-site redirects (default: 5)
  -H, --header <"K: V">      Extra request header
      --no-client-side       Skip client-side detection
      --json                 Print findings as JSON lines
  -s, --silent               Findings only
  -k, --insecure             Ignore TLS certificate errors
  -h, --help                 Show help
  -V, --version              Show version
`;

function die(msg) {
  console.error(c('31;1', `Error: ${msg}`));
  console.error('Run with --help for usage.');
  process.exit(2);
}

async function readStdin() {
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

function normalizeUrl(line) {
  line = line.trim();
  if (!line || line.startsWith('#')) return null;
  if (!/^https?:\/\//i.test(line)) line = 'http://' + line;
  try {
    new URL(line);
    return line;
  } catch {
    return null;
  }
}

async function main() {
  let values;

  try {
    ({ values } = parseArgs({
      options: {
        url: { type: 'string', short: 'u' },
        list: { type: 'string', short: 'l' },
        output: { type: 'string', short: 'o' },
        domain: { type: 'string', short: 'd', default: 'rh-canary.example' },
        mode: { type: 'string', short: 'm', default: 'both' },
        'common-params': { type: 'boolean', short: 'p' },
        concurrency: { type: 'string', short: 'c', default: '10' },
        timeout: { type: 'string', short: 't', default: '10000' },
        'max-redirects': { type: 'string', short: 'r', default: '5' },
        header: { type: 'string', short: 'H', multiple: true },
        'no-client-side': { type: 'boolean' },
        json: { type: 'boolean' },
        silent: { type: 'boolean', short: 's' },
        insecure: { type: 'boolean', short: 'k' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'V' }
      }
    }));
  } catch (e) {
    die(e.message);
  }

  if (values.version) return console.log(pkg.version);
  if (values.help) return console.log(HELP);

  if (!['param', 'path', 'both'].includes(values.mode)) {
    die('--mode must be param, path or both');
  }

  const num = (name, v, min) => {
    const n = Number(v);
    if (!Number.isInteger(n) || n < min) {
      die(`--${name} must be an integer >= ${min}`);
    }
    return n;
  };

  const headers = {};

  for (const h of values.header || []) {
    const i = h.indexOf(':');
    if (i < 1) die(`Invalid header "${h}" (expected "Name: value")`);
    headers[h.slice(0, i).trim()] = h.slice(i + 1).trim();
  }

  let lines = [];

  if (values.url) lines.push(values.url);

  if (values.list) {
    try {
      lines.push(...fs.readFileSync(values.list, 'utf8').split(/\r?\n/));
    } catch (e) {
      die(`Cannot read list file: ${e.message}`);
    }
  }

  if (!lines.length && !process.stdin.isTTY) {
    lines = (await readStdin()).split(/\r?\n/);
  }

  const targets = [...new Set(lines.map(normalizeUrl).filter(Boolean))];

  if (!targets.length) {
    if (!values.silent) banner();
    die('No valid target URLs. Use -u, -l, or pipe URLs through stdin.');
  }

  if (values.insecure) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }

  const opts = {
    domain: values.domain.toLowerCase(),
    mode: values.mode,
    commonParams: !!values['common-params'],
    timeout: num('timeout', values.timeout, 1),
    maxRedirects: num('max-redirects', values['max-redirects'], 0),
    clientSide: !values['no-client-side'],
    headers,
    userAgent: `RedirectHunter/${pkg.version}`
  };

  const concurrency = num('concurrency', values.concurrency, 1);
  const quiet = values.silent || values.json;

  if (!values.silent) banner();

  const jobs = [];

  for (const target of targets) {
    for (const test of buildTests(target, opts)) {
      jobs.push({ ...test, target });
    }
  }

  const parametersTested = [...new Set(
    jobs
      .filter((job) => job.kind === 'param' && job.param)
      .map((job) => job.param)
  )].sort();

  const metadata = {
    tool: 'RedirectHunter',
    toolVersion: pkg.version,
    startedAt: new Date().toISOString(),
    targets,
    settings: {
      mode: opts.mode,
      commonParamsEnabled: opts.commonParams,
      canaryDomain: opts.domain,
      concurrency,
      timeoutMs: opts.timeout,
      maxSameSiteRedirects: opts.maxRedirects,
      clientSideDetectionEnabled: opts.clientSide,
      insecureTls: !!values.insecure,
      customHeaderNames: Object.keys(headers)
    },
    coverage: {
      testsScheduled: jobs.length,
      parameterTestsScheduled: jobs.filter(
        (job) => job.kind === 'param'
      ).length,
      pathTestsScheduled: jobs.filter(
        (job) => job.kind === 'path'
      ).length,
      parametersTested
    }
  };

  if (!quiet) {
    console.error(
      `Targets: ${targets.length}  Tests scheduled: ${jobs.length}  ` +
      `Concurrency: ${concurrency}\n`
    );
  }

  const reporter = new Reporter({
    output: values.output,
    json: values.json,
    quiet,
    metadata
  });

  const reported = new Set();

  let jobsCompleted = 0;
  let probeAttempts = 0;
  let errors = 0;

  const startedMs = Date.now();

  process.on('SIGINT', () => {
    const durationMs = Date.now() - startedMs;

    reporter.finish({
      testsScheduled: jobs.length,
      jobsCompleted,
      probeAttempts,
      requestErrors: errors,
      findingsCount: reporter.findings.length,
      result: reporter.findings.length
        ? 'findings-detected'
        : 'no-findings-detected',
      durationMs,
      interrupted: true
    });

    process.exit(130);
  });

  await runPool(jobs, concurrency, async (job) => {
    const key = `${job.target}|${job.kind}|${job.param || ''}`;

    if (reported.has(key)) {
      jobsCompleted++;
      return;
    }

    probeAttempts++;

    const result = await probe(job, opts);

    jobsCompleted++;

    if (!quiet && process.stderr.isTTY) {
      process.stderr.write(`\r[${jobsCompleted}/${jobs.length}]`);
    }

    if (!result) return;

    if (result.error) {
      errors++;
      return;
    }

    if (reported.has(key)) return;

    reported.add(key);

    if (!quiet && process.stderr.isTTY) {
      process.stderr.write('\r\x1b[K');
    }

    reporter.add({
      target: job.target,
      url: job.url,
      kind: job.kind,
      param: job.param,
      payload: job.payload,
      ...result
    });
  });

  if (!quiet && process.stderr.isTTY) {
    process.stderr.write('\r\x1b[K');
  }

  const durationMs = Date.now() - startedMs;

  const summary = {
    testsScheduled: jobs.length,
    jobsCompleted,
    probeAttempts,
    requestErrors: errors,
    findingsCount: reporter.findings.length,
    result: reporter.findings.length
      ? 'findings-detected'
      : 'no-findings-detected',
    durationMs,
    interrupted: false
  };

  if (!quiet) {
    console.error(
      `Done. ${summary.findingsCount} vulnerable, ` +
      `${errors} request error(s). ` +
      `${probeAttempts} probe attempt(s) across ${jobs.length} scheduled test(s).`
    );
  }

  reporter.finish(summary);

  process.exitCode = reporter.findings.length ? 1 : 0;
}

main().catch((e) => die(e.stack || e.message));
