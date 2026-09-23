const SESSION_VERSION = 1;
const REPORT_FORMAT = "bugtape.local-report";
const MAX_EVENTS = 5_000;
const MAX_EVENT_BYTES = 20_000;
export const MAX_SESSION_DURATION_MS = 3_600_000;

export class DiagnosticError extends Error {
  constructor(message, path, code = "INVALID_SESSION") {
    super(message);
    this.name = "DiagnosticError";
    this.code = code;
    this.path = path;
  }
}

function clone(value) {
  return structuredClone(value);
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonEmpty(value, path) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new DiagnosticError(`${path} must be a non-empty string`, path);
  }
  return value;
}

function safePayload(value, path = "payload", depth = 0) {
  if (depth > 8) {
    throw new DiagnosticError(`${path} exceeds the maximum nesting depth`, path);
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry, index) => safePayload(entry, `${path}.${index}`, depth + 1));
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        safePayload(entry, `${path}.${key}`, depth + 1)
      ])
    );
  }
  throw new DiagnosticError(`${path} contains an unsupported value`, path);
}

function payloadSize(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

const excludedCaptureFields = new Map([
  ["formvalue", "form values"],
  ["formvalues", "form values"],
  ["formdata", "form values"],
  ["requestbody", "request bodies"],
  ["responsebody", "request bodies"],
  ["body", "request bodies"],
  ["header", "headers"],
  ["headers", "headers"],
  ["requestheaders", "headers"],
  ["responseheaders", "headers"],
  ["authorization", "headers"],
  ["authorisation", "headers"],
  ["cookie", "cookies"],
  ["cookies", "cookies"],
  ["setcookie", "cookies"],
  ["video", "video"],
  ["screenrecording", "video"]
]);

function assertCaptureBoundary(value, path) {
  if (Array.isArray(value)) {
    for (const [index, entry] of value.entries()) {
      assertCaptureBoundary(entry, `${path}.${index}`);
    }
    return;
  }
  if (!isRecord(value)) {
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    const normalisedKey = key.toLowerCase().replaceAll(/[^a-z0-9]/g, "");
    const excludedCategory = excludedCaptureFields.get(normalisedKey);
    if (excludedCategory) {
      throw new DiagnosticError(
        `${path}.${key} contains excluded ${excludedCategory}`,
        `${path}.${key}`,
        "EXCLUDED_CAPTURE_FIELD"
      );
    }
    assertCaptureBoundary(entry, `${path}.${key}`);
  }
}

function capturedValue(value, path) {
  const captured = safePayload(value, path);
  assertCaptureBoundary(captured, path);
  return captured;
}

function validateEvent(event, index, sessionDurationMs) {
  const path = `session.events.${index}`;
  if (!isRecord(event)) {
    throw new DiagnosticError(`${path} must be an object`, path);
  }
  if (!Number.isFinite(event.atMs) || event.atMs < 0 || event.atMs > sessionDurationMs + 1) {
    throw new DiagnosticError(`${path}.atMs is outside the session`, `${path}.atMs`);
  }
  const payload = capturedValue(event.payload ?? {}, `${path}.payload`);
  if (payloadSize(payload) > MAX_EVENT_BYTES) {
    throw new DiagnosticError(
      `${path}.payload exceeds ${MAX_EVENT_BYTES} bytes`,
      `${path}.payload`,
      "EVENT_TOO_LARGE"
    );
  }
  return {
    id: nonEmpty(event.id, `${path}.id`),
    sequence: Number.isInteger(event.sequence) ? event.sequence : index + 1,
    stream: nonEmpty(event.stream, `${path}.stream`),
    type: nonEmpty(event.type, `${path}.type`),
    atMs: event.atMs,
    payload
  };
}

export function validateSession(input) {
  if (!isRecord(input)) {
    throw new DiagnosticError("session must be an object", "session");
  }
  if (input.version !== SESSION_VERSION) {
    throw new DiagnosticError(
      `session.version must be ${SESSION_VERSION}`,
      "session.version",
      "UNSUPPORTED_SESSION"
    );
  }
  if (!isRecord(input.clock) || input.clock.type !== "monotonic-relative") {
    throw new DiagnosticError(
      "session.clock.type must be monotonic-relative",
      "session.clock.type"
    );
  }
  const durationMs = input.durationMs;
  if (
    !Number.isFinite(durationMs) ||
    durationMs < 0 ||
    durationMs > MAX_SESSION_DURATION_MS
  ) {
    throw new DiagnosticError(
      `session.durationMs must be between 0 and ${MAX_SESSION_DURATION_MS}`,
      "session.durationMs"
    );
  }
  if (!Array.isArray(input.streams)) {
    throw new DiagnosticError("session.streams must be an array", "session.streams");
  }
  if (!Array.isArray(input.events)) {
    throw new DiagnosticError("session.events must be an array", "session.events");
  }
  if (input.events.length > MAX_EVENTS) {
    throw new DiagnosticError(
      `session.events exceeds the limit of ${MAX_EVENTS}`,
      "session.events",
      "SESSION_TOO_LARGE"
    );
  }
  const events = input.events.map((event, index) =>
    validateEvent(event, index, durationMs)
  );
  const eventIds = new Set();
  for (const [index, event] of events.entries()) {
    if (eventIds.has(event.id)) {
      throw new DiagnosticError(
        `event id "${event.id}" is duplicated`,
        `session.events.${index}.id`
      );
    }
    eventIds.add(event.id);
  }
  return {
    version: SESSION_VERSION,
    id: nonEmpty(input.id, "session.id"),
    title: nonEmpty(input.title, "session.title"),
    startedAt: nonEmpty(input.startedAt, "session.startedAt"),
    durationMs,
    clock: {
      type: "monotonic-relative",
      startedMonotonicMs: Number(input.clock.startedMonotonicMs ?? 0),
      stoppedMonotonicMs: Number(input.clock.stoppedMonotonicMs ?? durationMs)
    },
    streams: [...new Set(input.streams.map(String))],
    environment: capturedValue(input.environment ?? {}, "session.environment"),
    events
  };
}

function finiteNumber(value, path) {
  const number = Number(value ?? 0);
  if (!Number.isFinite(number)) {
    throw new DiagnosticError(`${path} must be a finite number`, path);
  }
  return number;
}

function networkMetadata(payload, path = "payload") {
  let host = String(payload.host ?? "");
  if (payload.url) {
    try {
      host = new URL(String(payload.url)).host;
    } catch {
      host = "invalid-url";
    }
  }
  return {
    method: String(payload.method ?? "GET").toUpperCase(),
    host,
    status: finiteNumber(payload.status, `${path}.status`),
    durationMs: finiteNumber(payload.durationMs, `${path}.durationMs`),
    sizeBytes: finiteNumber(payload.sizeBytes, `${path}.sizeBytes`)
  };
}

export class DiagnosticRecorder {
  #now;
  #wallNow;
  #state = "idle";
  #session;
  #startedMono = 0;
  #pausedAt = 0;
  #pausedTotal = 0;
  #sequence = 0;

  constructor({
    monotonicNow = () => performance.now(),
    wallNow = () => new Date()
  } = {}) {
    this.#now = monotonicNow;
    this.#wallNow = wallNow;
  }

  get state() {
    return this.#state;
  }

  start({ confirmed, streams, title = "Diagnostic reproduction", environment = {} }) {
    if (this.#state !== "idle") {
      throw new DiagnosticError("Recorder has already started", "recorder.state", "INVALID_STATE");
    }
    if (confirmed !== true) {
      throw new DiagnosticError(
        "Enabled streams must be confirmed before recording",
        "confirmed",
        "CONFIRMATION_REQUIRED"
      );
    }
    if (!Array.isArray(streams) || streams.length === 0) {
      throw new DiagnosticError("Select at least one diagnostic stream", "streams");
    }
    const enabledStreams = streams.map((stream, index) =>
      nonEmpty(stream, `streams.${index}`)
    );
    nonEmpty(title, "title");
    const capturedEnvironment = capturedValue(environment, "environment");
    this.#startedMono = this.#now();
    const startedAt = this.#wallNow().toISOString();
    this.#session = {
      version: SESSION_VERSION,
      id: `session-${startedAt.replaceAll(/[^0-9]/g, "").slice(0, 14)}`,
      title,
      startedAt,
      durationMs: 0,
      clock: {
        type: "monotonic-relative",
        startedMonotonicMs: this.#startedMono,
        stoppedMonotonicMs: this.#startedMono
      },
      streams: [...new Set(enabledStreams)],
      environment: capturedEnvironment,
      events: []
    };
    this.#state = "recording";
    return this.snapshot();
  }

  #elapsed() {
    if (this.#state === "stopped") {
      return this.#session.durationMs;
    }
    const current = this.#state === "paused" ? this.#pausedAt : this.#now();
    return Math.max(0, current - this.#startedMono - this.#pausedTotal);
  }

  append(stream, type, payload = {}) {
    if (this.#state !== "recording") {
      throw new DiagnosticError(
        "Events can only be recorded while active",
        "recorder.state",
        "INVALID_STATE"
      );
    }
    if (!this.#session.streams.includes(stream) && stream !== "markers") {
      throw new DiagnosticError(
        `Stream "${stream}" was not enabled`,
        "stream",
        "STREAM_DISABLED"
      );
    }
    if (this.#session.events.length >= MAX_EVENTS) {
      throw new DiagnosticError(
        `Recorder event count cannot exceed ${MAX_EVENTS}`,
        "recorder.events",
        "SESSION_TOO_LARGE"
      );
    }
    nonEmpty(type, "type");
    const atMs = this.#elapsed();
    if (atMs > MAX_SESSION_DURATION_MS) {
      throw new DiagnosticError(
        "Recording has reached its one-hour limit",
        "recorder.durationMs",
        "SESSION_TOO_LONG"
      );
    }
    let capturedPayload = safePayload(payload);
    if (stream === "network") {
      capturedPayload = networkMetadata(capturedPayload);
    }
    assertCaptureBoundary(capturedPayload, "payload");
    if (payloadSize(capturedPayload) > MAX_EVENT_BYTES) {
      throw new DiagnosticError(
        `Event payload exceeds ${MAX_EVENT_BYTES} bytes`,
        "payload",
        "EVENT_TOO_LARGE"
      );
    }
    const sequence = this.#sequence + 1;
    // Check the event exactly as stop() will, so nothing accepted here can
    // later stop the recording from being finalised.
    const event = validateEvent(
      { id: `event-${sequence}`, sequence, stream, type, atMs, payload: capturedPayload },
      this.#session.events.length,
      atMs
    );
    this.#sequence = sequence;
    this.#session.events.push(event);
    return clone(event);
  }

  marker(label) {
    return this.append("markers", "written-marker", { label: String(label) });
  }

  pause() {
    if (this.#state !== "recording") {
      throw new DiagnosticError("Only an active recording can pause", "recorder.state", "INVALID_STATE");
    }
    this.#pausedAt = this.#now();
    this.#state = "paused";
  }

  resume() {
    if (this.#state !== "paused") {
      throw new DiagnosticError("Only a paused recording can resume", "recorder.state", "INVALID_STATE");
    }
    this.#pausedTotal += this.#now() - this.#pausedAt;
    this.#state = "recording";
  }

  stop() {
    if (!["recording", "paused"].includes(this.#state)) {
      throw new DiagnosticError("No recording is available to stop", "recorder.state", "INVALID_STATE");
    }
    const stoppedMono = this.#state === "paused" ? this.#pausedAt : this.#now();
    const stoppedSession = clone(this.#session);
    stoppedSession.durationMs = Math.min(this.#elapsed(), MAX_SESSION_DURATION_MS);
    stoppedSession.clock.stoppedMonotonicMs = stoppedMono;
    const validated = validateSession(stoppedSession);
    this.#session = validated;
    this.#state = "stopped";
    return clone(validated);
  }

  snapshot() {
    if (!this.#session) {
      return undefined;
    }
    const session = clone(this.#session);
    session.durationMs = Math.min(this.#elapsed(), MAX_SESSION_DURATION_MS);
    session.clock.stoppedMonotonicMs =
      this.#state === "paused" ? this.#pausedAt : this.#now();
    return session;
  }
}

export function buildTimeline(input) {
  const session = validateSession(input);
  return [...session.events].sort(
    (left, right) => left.atMs - right.atMs || left.sequence - right.sequence
  );
}

const patterns = [
  {
    category: "bearer-token",
    expression: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi
  },
  {
    category: "email-address",
    expression: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
  },
  {
    category: "api-key",
    expression: /\b(?:sk|pk|api)[_-][A-Za-z0-9_-]{12,}\b/gi
  },
  {
    category: "url-query",
    expression: /https?:\/\/[^\s?]+\?[^\s]+/gi
  }
];

function displayPayloadPath(segments) {
  return `payload${segments
    .map((segment) =>
      typeof segment === "number" ? `[${segment}]` : `[${JSON.stringify(segment)}]`
    )
    .join("")}`;
}

function stringEntries(value, pathSegments = []) {
  if (typeof value === "string") {
    return [{
      path: displayPayloadPath(pathSegments),
      pathSegments: [...pathSegments],
      value
    }];
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      stringEntries(entry, [...pathSegments, index])
    );
  }
  if (isRecord(value)) {
    return Object.entries(value).flatMap(([key, entry]) =>
      stringEntries(entry, [...pathSegments, key])
    );
  }
  return [];
}

function maskedPreview(value, start, length) {
  const before = value.slice(Math.max(0, start - 10), start);
  const after = value.slice(start + length, start + length + 10);
  return `${before}[sensitive ${length} chars]${after}`;
}

export function scanSensitiveData(input) {
  const session = validateSession(input);
  const findings = [];
  for (const event of session.events) {
    for (const entry of stringEntries(event.payload)) {
      for (const pattern of patterns) {
        pattern.expression.lastIndex = 0;
        for (const match of entry.value.matchAll(pattern.expression)) {
          findings.push({
            id: `finding-${event.id}-${findings.length + 1}`,
            eventId: event.id,
            path: entry.path,
            pathSegments: [...entry.pathSegments],
            category: pattern.category,
            start: match.index,
            length: match[0].length,
            preview: maskedPreview(entry.value, match.index, match[0].length)
          });
        }
      }
    }
  }
  return findings;
}

function replaceAtPath(value, segments, replacer) {
  let cursor = value;
  for (let index = 0; index < segments.length - 1; index += 1) {
    if (!isRecord(cursor) && !Array.isArray(cursor)) {
      throw new DiagnosticError(
        "Redaction path does not resolve to a payload value",
        "findings.pathSegments",
        "INVALID_FINDING"
      );
    }
    cursor = cursor[segments[index]];
  }
  const finalKey = segments.at(-1);
  if (
    finalKey === undefined ||
    (!isRecord(cursor) && !Array.isArray(cursor)) ||
    typeof cursor[finalKey] !== "string"
  ) {
    throw new DiagnosticError(
      "Redaction path must resolve to a string payload value",
      "findings.pathSegments",
      "INVALID_FINDING"
    );
  }
  cursor[finalKey] = replacer(cursor[finalKey]);
}

function redactSpans(text, entries) {
  for (const { finding, index } of entries) {
    if (
      !Number.isInteger(finding.start) ||
      !Number.isInteger(finding.length) ||
      finding.start < 0 ||
      finding.length <= 0 ||
      finding.start + finding.length > text.length
    ) {
      throw new DiagnosticError(
        "Finding start and length must fall within the value it redacts",
        `findings.${index}`,
        "INVALID_FINDING"
      );
    }
  }
  // Overlapping findings (an email inside a URL, a key inside a query string)
  // are merged first, so replacing one never shifts the offsets of another.
  const spans = [];
  for (const { finding } of [...entries].sort(
    (left, right) => left.finding.start - right.finding.start
  )) {
    const end = finding.start + finding.length;
    const category = String(finding.category);
    const previous = spans.at(-1);
    if (previous && finding.start < previous.end) {
      previous.end = Math.max(previous.end, end);
      if (!previous.categories.includes(category)) {
        previous.categories.push(category);
      }
    } else {
      spans.push({ start: finding.start, end, categories: [category] });
    }
  }
  let result = text;
  for (const span of spans.reverse()) {
    result =
      result.slice(0, span.start) +
      `[REDACTED:${span.categories.join(",")}]` +
      result.slice(span.end);
  }
  return result;
}

export function mergeReviewPolicy(...policies) {
  const merged = {
    redactFindingIds: new Set(),
    removeEventIds: new Set(),
    removeStreams: new Set()
  };
  for (const policy of policies) {
    for (const key of Object.keys(merged)) {
      for (const value of policy?.[key] ?? []) {
        merged[key].add(String(value));
      }
    }
  }
  return Object.fromEntries(
    Object.entries(merged).map(([key, values]) => [key, [...values]])
  );
}

export function applyReview(
  input,
  {
    findings = scanSensitiveData(input),
    redactFindingIds = findings.map((finding) => finding.id),
    removeEventIds = [],
    removeStreams = []
  } = {}
) {
  const session = validateSession(input);
  const removedEvents = new Set(removeEventIds);
  const removedStreams = new Set(removeStreams);
  const reviewed = clone(session);
  reviewed.events = reviewed.events.filter(
    (event) => !removedEvents.has(event.id) && !removedStreams.has(event.stream)
  );
  const accepted = new Set(redactFindingIds);
  const groupedByEvent = new Map();
  for (const [index, finding] of findings.entries()) {
    if (!accepted.has(finding.id)) {
      continue;
    }
    if (
      !Array.isArray(finding.pathSegments) ||
      finding.pathSegments.some(
        (segment) => typeof segment !== "string" && !Number.isInteger(segment)
      )
    ) {
      throw new DiagnosticError(
        "Finding pathSegments must contain string or integer segments",
        `findings.${index}.pathSegments`,
        "INVALID_FINDING"
      );
    }
    const eventGroups = groupedByEvent.get(finding.eventId) ?? new Map();
    const pathKey = JSON.stringify(finding.pathSegments);
    const group = eventGroups.get(pathKey) ?? {
      pathSegments: [...finding.pathSegments],
      findings: []
    };
    group.findings.push({ finding, index });
    eventGroups.set(pathKey, group);
    groupedByEvent.set(finding.eventId, eventGroups);
  }
  for (const [eventId, eventGroups] of groupedByEvent) {
    const event = reviewed.events.find((entry) => entry.id === eventId);
    if (!event) {
      continue;
    }
    for (const group of eventGroups.values()) {
      replaceAtPath(event.payload, group.pathSegments, (text) =>
        redactSpans(text, group.findings)
      );
    }
  }
  return validateSession(reviewed);
}

function eventSummary(event) {
  if (event.stream === "network") {
    return `${event.payload.method} ${event.payload.host} → ${event.payload.status} in ${event.payload.durationMs} ms`;
  }
  if (event.stream === "console") {
    return `${event.payload.level ?? "log"}: ${event.payload.message ?? "No message"}`;
  }
  if (event.stream === "interactions") {
    return `${event.type}: ${event.payload.target ?? "unnamed control"}`;
  }
  if (event.stream === "markers") {
    return `marker: ${event.payload.label ?? "unlabelled"}`;
  }
  return event.type;
}

function markdownSafe(value) {
  return String(value)
    .replaceAll(/\r?\n/g, " ")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll(/[\\`*_[\]{}()#+.!|:@]/g, (character) => {
      return `&#${character.codePointAt(0)};`;
    });
}

export function privacyManifest(input) {
  const session = validateSession(input);
  const hosts = [
    ...new Set(
      session.events
        .filter((event) => event.stream === "network" && event.payload.host)
        .map((event) => event.payload.host)
    )
  ].sort();
  return {
    streams: [...new Set(session.events.map((event) => event.stream))].sort(),
    hosts,
    includesFormValues: false,
    includesRequestBodies: false,
    includesHeaders: false,
    includesCookies: false,
    includesVideo: false
  };
}

export function createPortableReport(input) {
  const session = validateSession(input);
  return {
    format: REPORT_FORMAT,
    version: 1,
    session,
    privacy: privacyManifest(session)
  };
}

export function validateReport(input) {
  if (!isRecord(input) || input.format !== REPORT_FORMAT) {
    throw new DiagnosticError(
      `report.format must be ${REPORT_FORMAT}`,
      "report.format",
      "UNSUPPORTED_REPORT"
    );
  }
  if (input.version !== 1) {
    throw new DiagnosticError("report.version must be 1", "report.version", "UNSUPPORTED_REPORT");
  }
  return createPortableReport(validateSession(input.session));
}

export function createMarkdownReport(input) {
  const session = validateSession(input);
  const privacy = privacyManifest(session);
  const lines = [
    `# ${markdownSafe(session.title)}`,
    "",
    "## Reproduction evidence",
    "",
    `- Session started: ${markdownSafe(session.startedAt)}`,
    `- Duration: ${(session.durationMs / 1000).toFixed(2)} seconds`,
    `- Captured streams: ${privacy.streams.map(markdownSafe).join(", ") || "none"}`,
    `- Network hosts: ${privacy.hosts.map(markdownSafe).join(", ") || "none"}`,
    "- Form values, request bodies, headers, cookies and video: not captured",
    "",
    "## Synchronised timeline",
    ""
  ];
  for (const event of buildTimeline(session)) {
    lines.push(
      `- ${event.atMs.toFixed(0)} ms — ${markdownSafe(eventSummary(event))}`
    );
  }
  lines.push(
    "",
    "## Environment",
    "",
    `- Browser: ${markdownSafe(session.environment.browser ?? "not recorded")}`,
    `- Viewport: ${markdownSafe(session.environment.viewport ?? "not recorded")}`,
    `- Platform: ${markdownSafe(session.environment.platform ?? "not recorded")}`,
    "",
    "This report is synchronised diagnostic evidence, not deterministic application replay."
  );
  return lines.join("\n");
}
