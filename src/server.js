import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const roots = new Map([
  ["public", resolve(root, "public")],
  ["src", resolve(root, "src")],
  ["examples", resolve(root, "examples")]
]);
const types = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8"
};
const baseHeaders = {
  "cache-control": "no-store",
  "content-security-policy":
    "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff"
};

function fileFor(pathname) {
  if (pathname.includes("\0")) {
    return undefined;
  }
  if (pathname === "/") {
    return resolve(roots.get("public"), "index.html");
  }
  const parts = pathname.slice(1).split("/");
  const namedRoot = roots.get(parts[0]);
  const base = namedRoot ?? roots.get("public");
  const relative = namedRoot ? parts.slice(1).join("/") : parts.join("/");
  const candidate = resolve(base, `.${sep}${relative}`);
  return candidate.startsWith(`${base}${sep}`) ? candidate : undefined;
}

function sendText(response, status, message, headers = {}) {
  response.writeHead(status, {
    ...baseHeaders,
    ...headers,
    "content-type": "text/plain; charset=utf-8"
  });
  response.end(message);
}

export function createBugtapeServer() {
  return createServer(async (request, response) => {
    if (request.method !== "GET" && request.method !== "HEAD") {
      sendText(response, 405, "Method not allowed", { allow: "GET, HEAD" });
      return;
    }
    let file;
    try {
      // Only the path is used, so the Host header never has to parse.
      const url = new URL(request.url ?? "/", "http://localhost");
      file = fileFor(decodeURIComponent(url.pathname));
    } catch {
      file = undefined;
    }
    if (!file) {
      sendText(response, 400, "Invalid path");
      return;
    }
    try {
      const body = await readFile(file);
      response.writeHead(200, {
        ...baseHeaders,
        "content-length": body.byteLength,
        "content-type": types[extname(file)] ?? "application/octet-stream"
      });
      response.end(request.method === "HEAD" ? undefined : body);
    } catch (error) {
      const missing = ["ENOENT", "EISDIR", "ENOTDIR"].includes(error?.code);
      sendText(response, missing ? 404 : 500, missing ? "Not found" : "Server error");
    }
  });
}

function isEntryPoint() {
  return Boolean(process.argv[1]) &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
}

if (isEntryPoint()) {
  const host = process.env.HOST ?? "127.0.0.1";
  const port = Number.parseInt(process.env.PORT ?? "4176", 10);
  const server = createBugtapeServer();

  server.listen(port, host, () => {
    const address = server.address();
    const actualPort = typeof address === "object" && address ? address.port : port;
    console.log(`Bugtape listening at http://${host}:${actualPort}`);
  });

  const shutdown = () => {
    server.close((error) => {
      process.exitCode = error ? 1 : 0;
    });
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
