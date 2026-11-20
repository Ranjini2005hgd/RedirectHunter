
'use strict';

const fs = require('fs');

const useColor = () =>
  process.stdout.isTTY && !process.env.NO_COLOR;

const c = (code, s) =>
  useColor() ? `\x1b[${code}m${s}\x1b[0m` : s;

const banner = () => {
  const lines = [
    '',
    ' .-----------------------------.',
    ' |  Tool   : RedirectHunter    |',
    ' |  Open Redirect Scanner      |',
    "  '-----------------------------'",
    ''
  ];

  console.error(c('36;1', lines.join('\n')));
};

function formatFinding(f) {
  const where = f.kind === 'param'
    ? `param "${f.param}"`
    : 'path';

  return [
    `${c('31;1', '[VULNERABLE]')} ${c('34;1', f.target)}  ` +
      `${c('33', `(${f.type}, ${where}, ${f.status})`)}`,
    `  Payload : ${f.payload}`,
    `  Location: ${f.location}`,
    `  PoC     : ${f.url}`,
    ''
  ].join('\n');
}

class Reporter {
  constructor({ output, json, quiet, metadata }) {
    this.output = output;
    this.json = json;
    this.quiet = quiet;
    this.metadata = metadata;
    this.findings = [];
  }

  add(finding) {
    this.findings.push(finding);

    if (this.json) {
      console.log(JSON.stringify(finding));
    } else {
      console.log(formatFinding(finding));
    }
  }

  finish(summary) {
    if (!this.output) return;

    const asJson =
      this.json || this.output.toLowerCase().endsWith('.json');

    if (asJson) {
      const report = {
        reportFormat: 'RedirectHunter scan report',
        reportVersion: 1,

        scan: {
          ...this.metadata,
          completedAt: new Date().toISOString(),
          durationMs: summary.durationMs,
          status: summary.interrupted
            ? 'interrupted'
            : 'completed'
        },

        summary,

        findings: this.findings,

        limitations: [
          'A scan only evaluates the targets, paths, parameters, and payloads included in this run.',
          'Zero findings do not prove that a website is secure or free of open redirects.',
          'Probe attempts are scanner test cases; one probe may perform multiple HTTP requests when following same-site redirects.',
          'Client-side redirect detection uses pattern matching and may miss complex JavaScript behavior.',
          'Only scan systems you own or have explicit authorization to test.'
        ]
      };

      fs.writeFileSync(
        this.output,
        JSON.stringify(report, null, 2) + '\n'
      );
    } else {
      const data = this.findings
        .map((finding) => finding.url)
        .join('\n') +
        (this.findings.length ? '\n' : '');

      fs.writeFileSync(this.output, data);
    }

    if (!this.quiet) {
      console.error(
        `Saved ${asJson ? 'scan report' : 'PoC URLs'} to ${this.output}`
      );
    }
  }
}

module.exports = {
  Reporter,
  banner,
  c
};
