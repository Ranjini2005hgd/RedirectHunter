# RedirectHunter

\<p align="center">   \<img src="images/banner.png" alt="RedirectHunter - Developed by Ranjini U" width="100%"> \</p>

## Badges

\

![Uploading RedirectHunter Cybersecurity Banner.png…]()

## License

[MIT License](LICENSE)

## Installation

Requires Node.js 18+. No runtime dependencies.

```bash
npm install -g .
# Or run directly:
node index.js
```

## Usage

```bash
RedirectHunter -u "https://target.tld/login?next=/home"
RedirectHunter -l urls.txt -p -c 20 -o out.json
cat urls.txt | RedirectHunter --json -s
```

> Only scan targets you own or have written authorization to test.

## How It Works

1. For each URL, it builds test requests in two ways:
   - **Parameter mode:** Replaces query parameter values and, with `-p`, tests common names such as `next`, `url`, and `redirect_uri`.
   - **Path mode:** Appends payloads such as `//canary.example` to the path.
2. Requests are sent without automatically following redirects. Same-site redirects are followed manually.
3. Findings are reported when a redirect points to the configured canary domain.

## Options

| Option                | Description                                        |
| :-------------------- | :------------------------------------------------- |
| `-u, --url`           | Target URL                                         |
| `-l, --list`          | File of URLs (one per line, `#` comments allowed)  |
| `-o, --output`        | Save findings (`.json` → JSON, otherwise PoC URLs) |
| `-d, --domain`        | Canary domain (default `rh-canary.example`)        |
| `-m, --mode`          | `param`, `path` or `both`                          |
| `-p, --common-params` | Also try common redirect parameter names           |
| `-c, --concurrency`   | Parallel requests (default 10)                     |
| `-t, --timeout`       | Per-request timeout in ms (default 10000)          |
| `-r, --max-redirects` | Same-site redirects to follow (default 5)          |
| `-H, --header`        | Extra header, repeatable                           |
| `--no-client-side`    | Skip meta-refresh / JS redirect detection          |
| `--json`              | JSON-lines output                                  |
| `-s, --silent`        | Findings only                                      |
| `-k, --insecure`      | Ignore TLS errors                                  |

**Exit codes:** `1` if a vulnerability is found, `0` otherwise, and `2` for usage errors.

## Tests

```bash
npm test
```

## Developer

**Ranjini U**

MCA – Ethical Hacking and Cyber Forensic
S-VYASA University, Bengaluru, Karnataka, India.

**Areas of Interest:** Cybersecurity | Ethical Hacking | Digital Forensics

## Connect With Me

- **GitHub:** [Ranjini U](https://github.com/YOUR-GITHUB-USERNAME)
- **LinkedIn:** [My LinkedIn Profile](https://www.linkedin.com/in/YOUR-LINKEDIN-USERNAME/)
- **Portfolio:** Add your portfolio link here.

## Acknowledgements

Thanks to the original RedirectHunter author for the original project.

## Feedback

For feedback or collaboration, connect with me through my LinkedIn profile.
