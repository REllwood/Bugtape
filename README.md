<div align="center">

# Bugtape

**A privacy-conscious browser flight recorder for bug reports people can replay.**

[![License: MIT](https://img.shields.io/badge/license-MIT-2f6f4e?style=flat-square)](LICENSE)
![Node 22+](https://img.shields.io/badge/node-%3E%3D22-43853d?style=flat-square&logo=node.js&logoColor=white)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-555?style=flat-square)

</div>

A screen recording shows a bug happening but not why. Bugtape puts clicks, console messages and network requests on one timeline, then helps you strip anything sensitive before the report goes anywhere.

## What it does

- Asks you to confirm which streams to record before it starts
- Records interaction, console, network and marker events against one clock
- Drops query strings and request bodies at capture time
- Scans recorded text for sensitive patterns, and lets you remove single events or whole streams
- Exports validated JSON and a clean Markdown report ready to paste into an issue

## Quick start

Requires Node.js 22 or newer. No `npm install` needed.

```sh
git clone https://github.com/REllwood/Bugtape.git
cd Bugtape
npm start
```

Open http://127.0.0.1:4176 and record a session, or press **Load checkout fixture** for a sample checkout failure. Scan and review the draft, then export the report.

## Status

v0.1 is a local web prototype. It records events from its own page and imports saved sessions, but it doesn't capture other tabs, screen video or live browser traffic yet. A browser extension that does is next, along with Playwright reproduction scripts.

## Development

```sh
npm test        # recorder and redaction tests
npm run check   # tests plus syntax checks
```

## License

[MIT](LICENSE)
