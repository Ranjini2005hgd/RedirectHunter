![Logo](https://github.com/karthi-the-hacker/RedirectHunter/raw/main/images/logo.gif)

## Badges

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Follow Twitter](https://img.shields.io/twitter/follow/karthithehacker?style=social)](https://twitter.com/karthithehacker)

## License

[MIT](https://choosealicense.com/licenses/mit/)

## Installation

Requires Node.js 18+. No runtime dependencies.

```bash
npm install -g .          # or: node index.js ...
```

## Usage

```bash
RedirectHunter -u "https://target.tld/login?next=/home"     # scan one URL
RedirectHunter -l urls.txt -p -c 20 -o out.json             # list + common redirect params
cat urls.txt | RedirectHunter --json -s                     # pipe-friendly
```

> Only scan targets you own or have written authorization to test.

## How it works

1. For each URL it builds test requests two ways:
   - **param mode** – replaces every query parameter value (and, with `-p`, ~25 common names like `next`, `url`, `redirect_uri`) with redirect payloads, including host-aware whitelist-bypass tricks.
   - **path mode** – appends payloads such as `//canary.example` to the path.
2. Requests are sent **without auto-following redirects**. Same-site hops are followed manually; a finding is reported when a `Location` header (or meta-refresh / `location=` in HTML) points at the canary domain.
3. The canary domain is never contacted, so no traffic leaves your target.

## Options

| Option | Description |
| :-- | :-- |
| `-u, --url` | Target URL |
| `-l, --list` | File of URLs (one per line, `#` comments allowed) |
| `-o, --output` | Save findings (`.json` → JSON, otherwise PoC URLs) |
| `-d, --domain` | Canary domain (default `rh-canary.example`) |
| `-m, --mode` | `param`, `path` or `both` (default) |
| `-p, --common-params` | Also try common redirect parameter names |
| `-c, --concurrency` | Parallel requests (default 10) |
| `-t, --timeout` | Per-request timeout in ms (default 10000) |
| `-r, --max-redirects` | Same-site redirects to follow (default 5) |
| `-H, --header` | Extra header, repeatable (e.g. `-H "Cookie: a=b"`) |
| `--no-client-side` | Skip meta-refresh / JS redirect detection |
| `--json` | JSON-lines output |
| `-s, --silent` | Findings only |
| `-k, --insecure` | Ignore TLS errors |

Exit code is `1` if anything vulnerable was found, `0` otherwise, `2` on usage errors.

## Tests

```bash
npm test
```

## 🔗 Links

[![portfolio](https://img.shields.io/badge/my_portfolio-000?style=for-the-badge&logo=ko-fi&logoColor=white)](https://karthithehacker.com/)
[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/karthikeyan--v/)
[![twitter](https://img.shields.io/badge/twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://twitter.com/karthithehacker)

## Author

- [@karthithehacker](https://github.com/karthi-the-hacker/)

## Feedback

If you have any feedback, please reach out to us at contact@karthithehacker.com
