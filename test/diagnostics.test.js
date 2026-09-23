import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  DiagnosticRecorder,
  applyReview,
  buildTimeline,
  createMarkdownReport,
  createPortableReport,
  mergeReviewPolicy,
  scanSensitiveData,
  validateReport,
  validateSession
} from "../src/diagnostics.js";

const fixtureUrl = new URL("../examples/checkout-session.json", import.meta.url);
const fixture = validateSession(JSON.parse(await readFile(fixtureUrl, "utf8")));

test("recording requires explicit stream confirmation", () => {
  const recorder = new DiagnosticRecorder({ monotonicNow: () => 0 });
  assert.throws(
    () => recorder.start({ confirmed: false, streams: ["console"] }),
    (error) => error.code === "CONFIRMATION_REQUIRED"
  );
});

test("events share a monotonic relative clock and preserve tie order", () => {
  let now = 1_000;
  const recorder = new DiagnosticRecorder({
    monotonicNow: () => now,
    wallNow: () => new Date("2026-07-24T00:00:00.000Z")
  });
  recorder.start({ confirmed: true, streams: ["interactions", "console"] });
  now = 1_250;
  recorder.append("interactions", "click", { target: "Save" });
  recorder.append("console", "error", { message: "Failed" });
  now = 1_800;
  const session = recorder.stop();
  assert.deepEqual(
    buildTimeline(session).map((event) => [event.atMs, event.stream]),
    [[250, "interactions"], [250, "console"]]
  );
  assert.equal(session.durationMs, 800);
});

test("paused time is excluded from the session clock", () => {
  let now = 100;
  const recorder = new DiagnosticRecorder({ monotonicNow: () => now });
  recorder.start({ confirmed: true, streams: ["console"] });
  now = 300;
  recorder.pause();
  now = 1_300;
  recorder.resume();
  now = 1_500;
  recorder.append("console", "log", { message: "after pause" });
  const session = recorder.stop();
  assert.equal(session.events[0].atMs, 400);
  assert.equal(session.durationMs, 400);
});

test("a stopped recorder keeps its final duration stable", () => {
  let now = 100;
  const recorder = new DiagnosticRecorder({ monotonicNow: () => now });
  recorder.start({ confirmed: true, streams: ["console"] });
  now = 350;
  recorder.stop();
  now = 9_000;
  assert.equal(recorder.snapshot().durationMs, 250);
});

test("network capture keeps metadata and strips sensitive request fields", () => {
  let now = 0;
  const recorder = new DiagnosticRecorder({ monotonicNow: () => now });
  recorder.start({ confirmed: true, streams: ["network"] });
  now = 10;
  const event = recorder.append("network", "complete", {
    url: "https://api.example.test/path?secret=value",
    method: "post",
    status: 422,
    durationMs: 10,
    sizeBytes: 42,
    headers: { authorisation: "Bearer secret" },
    body: "private"
  });
  assert.deepEqual(event.payload, {
    method: "POST",
    host: "api.example.test",
    status: 422,
    durationMs: 10,
    sizeBytes: 42
  });
});

test("sensitive findings show masked previews and redact a derived copy", () => {
  const findings = scanSensitiveData(fixture);
  assert.ok(findings.some((finding) => finding.category === "email-address"));
  assert.ok(findings.some((finding) => finding.category === "bearer-token"));
  assert.ok(findings.every((finding) => !finding.preview.includes("reporter@example.test")));
  const reviewed = applyReview(fixture, { findings });
  const consoleEvent = reviewed.events.find((event) => event.stream === "console");
  assert.match(consoleEvent.payload.message, /\[REDACTED:email-address\]/);
  assert.match(consoleEvent.payload.message, /\[REDACTED:bearer-token\]/);
  assert.match(
    fixture.events.find((event) => event.stream === "console").payload.message,
    /reporter@example\.test/
  );
});

test("review can remove individual events and entire streams", () => {
  const reviewed = applyReview(fixture, {
    findings: [],
    redactFindingIds: [],
    removeEventIds: ["event-1"],
    removeStreams: ["console"]
  });
  assert.equal(reviewed.events.some((event) => event.id === "event-1"), false);
  assert.equal(reviewed.events.some((event) => event.stream === "console"), false);
});

test("review policy remains cumulative across repeated review passes", () => {
  const firstPolicy = mergeReviewPolicy({
    removeEventIds: ["event-1"],
    removeStreams: []
  });
  const cumulativePolicy = mergeReviewPolicy(firstPolicy, {
    removeEventIds: ["event-4"]
  });
  const reviewed = applyReview(fixture, {
    findings: [],
    redactFindingIds: [],
    ...cumulativePolicy
  });
  assert.equal(reviewed.events.some((event) => event.id === "event-1"), false);
  assert.equal(reviewed.events.some((event) => event.id === "event-4"), false);
});

test("structured redaction paths preserve colons and dotted property names", () => {
  const hostile = structuredClone(fixture);
  hostile.events[2].id = "console:event:3";
  hostile.events[2].payload = {
    "message.with.dot": "Contact dotted@example.test"
  };
  const findings = scanSensitiveData(hostile);
  const reviewed = applyReview(hostile, { findings });
  assert.equal(
    reviewed.events[2].payload["message.with.dot"],
    "Contact [REDACTED:email-address]"
  );
});

function consoleSession(message) {
  const session = structuredClone(fixture);
  session.events = [structuredClone(fixture.events[2])];
  session.events[0].payload = { level: "error", message };
  return session;
}

test("overlapping findings are redacted as one span without leaking text", () => {
  const session = consoleSession(
    "see https://api.test/reset?email=bob@ex.co&token=SUPERSECRET99 now"
  );
  const findings = scanSensitiveData(session);
  assert.deepEqual(
    findings.map((finding) => finding.category).sort(),
    ["email-address", "url-query"]
  );
  const reviewed = applyReview(session, { findings });
  assert.equal(
    reviewed.events[0].payload.message,
    "see [REDACTED:url-query,email-address] now"
  );
});

test("a long match inside a shorter placeholder keeps the text that follows", () => {
  const session = consoleSession(
    `https://x.test/?k=sk_${"A".repeat(40)} trailing context kept`
  );
  const reviewed = applyReview(session);
  assert.equal(
    reviewed.events[0].payload.message,
    "[REDACTED:url-query,api-key] trailing context kept"
  );
});

test("only accepted findings are redacted when findings overlap", () => {
  const session = consoleSession("see https://api.test/reset?email=bob@ex.co now");
  const findings = scanSensitiveData(session);
  const email = findings.find((finding) => finding.category === "email-address");
  const reviewed = applyReview(session, { findings, redactFindingIds: [email.id] });
  assert.equal(
    reviewed.events[0].payload.message,
    "see https://api.test/reset?email=[REDACTED:email-address] now"
  );
});

test("findings that do not fit the value they redact are rejected", () => {
  const session = consoleSession("short");
  const findings = [{
    id: "stale",
    eventId: session.events[0].id,
    pathSegments: ["message"],
    category: "email-address",
    start: 2,
    length: 40
  }];
  assert.throws(
    () => applyReview(session, { findings }),
    (error) => error.code === "INVALID_FINDING" && error.path === "findings.0"
  );
});

test("portable and Markdown reports disclose privacy limits", () => {
  const reviewed = applyReview(fixture);
  const report = createPortableReport(reviewed);
  assert.deepEqual(validateReport(report), report);
  assert.equal(report.privacy.includesFormValues, false);
  assert.equal(report.privacy.includesRequestBodies, false);
  assert.equal(report.privacy.includesVideo, false);
  const markdown = createMarkdownReport(reviewed);
  assert.match(markdown, /not deterministic application replay/);
  assert.doesNotMatch(markdown, /reporter@example\.test/);
});

test("oversized imports are rejected before event parsing", () => {
  const hostile = structuredClone(fixture);
  hostile.events = Array.from({ length: 5_001 }, (_, index) => ({
    id: `event-${index}`,
    stream: "console",
    type: "log",
    atMs: 1,
    payload: {}
  }));
  assert.throws(
    () => validateSession(hostile),
    (error) => error.code === "SESSION_TOO_LARGE" && error.path === "session.events"
  );
});

test("imports reject structured fields outside the documented capture boundary", () => {
  for (const [field, value] of [
    ["headers", { authorisation: "secret" }],
    ["requestBody", "private"],
    ["cookies", "session=secret"],
    ["formValues", { card: "private" }]
  ]) {
    const hostile = structuredClone(fixture);
    hostile.events[0].payload[field] = value;
    assert.throws(
      () => validateSession(hostile),
      (error) =>
        error.code === "EXCLUDED_CAPTURE_FIELD" &&
        error.path === `session.events.0.payload.${field}`
    );
  }
});

test("imports reject excluded fields nested in environment metadata", () => {
  const hostile = structuredClone(fixture);
  hostile.environment.runtime = {
    request: {
      headers: {
        authorisation: "Bearer private"
      }
    }
  };
  assert.throws(
    () => validateSession(hostile),
    (error) =>
      error.code === "EXCLUDED_CAPTURE_FIELD" &&
      error.path === "session.environment.runtime.request.headers"
  );
});

test("the recorder rejects excluded environment fields before it starts", () => {
  const recorder = new DiagnosticRecorder({ monotonicNow: () => 0 });
  assert.throws(
    () =>
      recorder.start({
        confirmed: true,
        streams: ["console"],
        environment: { nested: { cookies: "session=private" } }
      }),
    (error) =>
      error.code === "EXCLUDED_CAPTURE_FIELD" &&
      error.path === "environment.nested.cookies"
  );
  assert.equal(recorder.state, "idle");
});

test("Markdown reports neutralise active Markdown supplied by a recording", () => {
  const hostile = structuredClone(fixture);
  hostile.title = "Failure ![remote](https://example.test/title)";
  const consoleEvent = hostile.events.find((event) => event.stream === "console");
  consoleEvent.payload.message = "![tracker](https://example.test/pixel)";
  const markdown = createMarkdownReport(hostile);
  assert.doesNotMatch(markdown, /!\[(?:remote|tracker)\]\(https:/);
  assert.doesNotMatch(markdown, /https:\/\//);
  assert.match(
    markdown,
    /&#33;&#91;tracker&#93;&#40;https&#58;\/\/example&#46;test\/pixel&#41;/
  );
});

test("the recorder enforces its event limit before appending", () => {
  const recorder = new DiagnosticRecorder({ monotonicNow: () => 0 });
  recorder.start({ confirmed: true, streams: ["console"] });
  for (let index = 0; index < 5_000; index += 1) {
    recorder.append("console", "log", { index });
  }
  assert.throws(
    () => recorder.append("console", "log", { index: 5_000 }),
    (error) => error.code === "SESSION_TOO_LARGE"
  );
  assert.equal(recorder.snapshot().events.length, 5_000);
});

test("stop validates a candidate session before changing lifecycle state", () => {
  let now = 0;
  const recorder = new DiagnosticRecorder({ monotonicNow: () => now });
  recorder.start({ confirmed: true, streams: ["console"] });
  now = 3_600_001;
  assert.throws(
    () => recorder.stop(),
    (error) => error.path === "session.durationMs"
  );
  assert.equal(recorder.state, "recording");
});
