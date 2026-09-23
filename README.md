<div align="center">

# Bugtape

**A privacy-conscious browser flight recorder for bug reports people can replay.**

[![CI](https://github.com/REllwood/Bugtape/actions/workflows/ci.yml/badge.svg)](https://github.com/REllwood/Bugtape/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-2f6f4e?style=flat-square)](LICENSE)
![Node 22+](https://img.shields.io/badge/node-%3E%3D22-43853d?style=flat-square&logo=node.js&logoColor=white)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-555?style=flat-square)

</div>

A screen recording shows a bug happening but not why. Bugtape puts clicks, console messages and network requests on one timeline, then helps you strip anything sensitive before the report goes anywhere.

## What it does

- Asks you to confirm which streams to record before each recording
- Records interaction, console, network and marker events against one clock, for up to an hour
- Keeps only the method, host, status, timing and size of network requests, and only the target and category of interactions, so query strings, bodies, headers and form values never enter a session
- Refuses recorded or imported data with fields named like headers, cookies, bodies, credentials or form values
- Scans the title, environment details, event text and field names for email addresses, tokens, API keys, private keys, credentials, card and phone numbers, and URLs with query strings
- Lets you redact findings and remove single events or whole streams on a copy of the draft, and start the review again at any time
- Exports validated JSON and a clean Markdown report to download, copy or paste into an issue
- Imports saved sessions and JSON reports for another review

Scanning is pattern-based, so always read the draft yourself before sharing it.

## Quick start

Requires Node.js 22 or newer. No `npm install` needed.

```sh
git clone https://github.com/REllwood/Bugtape.git
cd Bugtape
npm start
```

Open http://127.0.0.1:4176 and record a session, press **Load checkout fixture** for a sample checkout failure, or press **Import saved session** to open a `.bugtape.json` file. Scan and review the draft, apply the review, then export the report.

Set `HOST` or `PORT` to serve somewhere other than `127.0.0.1:4176`.

## Status

v0.1 is a local web prototype. It records events from its own page and imports saved sessions and reports, but it doesn't capture other tabs, screen video or live browser traffic yet. A browser extension that does is next, along with Playwright reproduction scripts.

## Development

```sh
npm test        # recorder, redaction and server tests
npm run check   # tests plus a syntax check of every JavaScript file
```

GitHub Actions runs `npm run check` on Node 22 and 24 for every pull request and every push to `main`.

## License

[MIT](LICENSE)
