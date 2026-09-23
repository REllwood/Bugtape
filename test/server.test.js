import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { after, before, test } from "node:test";
import { createBugtapeServer } from "../src/server.js";

let server;
let port;

before(async () => {
  server = createBugtapeServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = server.address().port;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

// fetch() normalises paths before sending them, so raw requests are used to
// exercise encoded traversal and malformed escapes exactly as written.
function request(path, { method = "GET", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(
      { host: "127.0.0.1", port, path, method, headers },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8")
          })
        );
      }
    );
    outgoing.on("error", reject);
    outgoing.end();
  });
}

test("serves the page, shared module and fixture with the right types", async () => {
  for (const [path, type] of [
    ["/", "text/html; charset=utf-8"],
    ["/app.js", "text/javascript; charset=utf-8"],
    ["/src/diagnostics.js", "text/javascript; charset=utf-8"],
    ["/examples/checkout-session.json", "application/json; charset=utf-8"]
  ]) {
    const response = await request(path);
    assert.equal(response.status, 200, path);
    assert.equal(response.headers["content-type"], type, path);
  }
});

test("responses carry security headers", async () => {
  for (const path of ["/", "/missing.js"]) {
    const response = await request(path);
    assert.match(response.headers["content-security-policy"], /default-src 'self'/);
    assert.equal(response.headers["x-content-type-options"], "nosniff");
    assert.equal(response.headers["referrer-policy"], "no-referrer");
    assert.equal(response.headers["cache-control"], "no-store");
  }
});

test("object prototype names are treated as ordinary missing paths", async () => {
  for (const path of ["/constructor/x", "/__proto__/x", "/hasOwnProperty", "/toString/y"]) {
    assert.equal((await request(path)).status, 404, path);
  }
});

test("malformed escapes, traversal and null bytes are rejected", async () => {
  for (const path of [
    "/%E0%A4%A",
    "/%",
    "/src/..%2f..%2fpackage.json",
    "/..%2fpackage.json",
    "/examples/..%2f..%2f..%2fetc%2fpasswd",
    "/index.html%00.js"
  ]) {
    assert.equal((await request(path)).status, 400, path);
  }
});

test("missing files are 404 and directories are not listed", async () => {
  assert.equal((await request("/nope.js")).status, 404);
  assert.notEqual((await request("/src/")).status, 200);
});

test("an unusual Host header does not break the request", async () => {
  const response = await request("/", { headers: { host: "bad host[" } });
  assert.equal(response.status, 200);
});

test("HEAD returns headers only and other methods are refused", async () => {
  const head = await request("/", { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(head.body, "");
  assert.ok(Number(head.headers["content-length"]) > 0);
  const post = await request("/", { method: "POST" });
  assert.equal(post.status, 405);
  assert.equal(post.headers.allow, "GET, HEAD");
});
