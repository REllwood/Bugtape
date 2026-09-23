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

// Keys are compared after lowercasing and dropping punctuation, so
// "X-Auth-Header", "request_body_text" and "sessionCookie" are all caught.
// `keys` must match the whole name; `fragments` may appear anywhere in it.
const excludedCaptureFields = [
  {
    category: "form values",
    keys: ["value", "values"],
    fragments: ["formvalue", "formdata", "formfield", "inputvalue", "fieldvalue"]
  },
  { category: "request bodies", fragments: ["body"] },
  { category: "headers", fragments: ["header", "authorization", "authorisation"] },
  { category: "cookies", fragments: ["cookie"] },
  {
    category: "credentials",
    keys: ["auth", "token"],
    fragments: [
      "password",
      "passwd",
      "passphrase",
      "secret",
      "credential",
      "apikey",
      "privatekey",
      "accesstoken",
      "refreshtoken",
      "authtoken",
      "sessiontoken",
      "idtoken",
      "bearer"
    ]
  },
  { category: "video", fragments: ["video", "screenrecording", "screencapture"] }
];

function excludedCategory(key) {
  const normalisedKey = key.toLowerCase().replaceAll(/[^a-z0-9]/g, "");
  return excludedCaptureFields.find(
    ({ keys = [], fragments }) =>
      keys.includes(normalisedKey) ||
      fragments.some((fragment) => normalisedKey.includes(fragment))
  )?.category;
}

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
    const category = excludedCategory(key);
    if (category) {
      throw new DiagnosticError(
        `${path}.${key} contains excluded ${category}`,
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
  const stream = nonEmpty(event.stream, `${path}.stream`);
  const payload = streamMetadata(
    stream,
    capturedValue(event.payload ?? {}, `${path}.payload`),
    `${path}.payload`
  );
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
    stream,
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

function interactionMetadata(payload) {
  return {
    target: typeof payload.target === "string" ? payload.target : "unnamed control",
    category: typeof payload.category === "string" ? payload.category : "control",
    valueCaptured: false
  };
}

// Network and interaction events keep only an allowlisted set of fields,
// whether they were just recorded or imported from a saved session.
function streamMetadata(stream, payload, path) {
  if (stream === "network") {
    return networkMetadata(payload, path);
  }
  if (stream === "interactions") {
    return interactionMetadata(payload);
  }
  return payload;
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
    const capturedPayload = streamMetadata(stream, safePayload(payload), "payload");
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
    if (this.#state === "stopped") {
      return session;
    }
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

function passesLuhn(digits) {
  let sum = 0;
  for (const [index, digit] of [...digits].reverse().entries()) {
    let value = Number(digit);
    if (index % 2 === 1) {
      value *= 2;
      if (value > 9) {
        value -= 9;
      }
    }
    sum += value;
  }
  return sum % 10 === 0;
}

// Visa, Mastercard, American Express and Discover lengths and prefixes, so
// 13- and 14-digit timestamps or identifiers are not mistaken for cards.
const cardPrefixes = /^(?:4\d{15}(?:\d{3})?|5[1-5]\d{14}|2[2-7]\d{14}|3[47]\d{13}|6\d{15})$/;

const patterns = [
  {
    category: "private-key",
    expression:
      /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )*PRIVATE KEY-----|$)/g
  },
  {
    category: "bearer-token",
    expression: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi
  },
  {
    category: "jwt",
    expression: /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g
  },
  {
    category: "github-token",
    expression: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g
  },
  {
    category: "aws-access-key",
    expression: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g
  },
  {
    category: "slack-token",
    expression: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g
  },
  {
    category: "api-key",
    expression: /\b(?:sk|pk|api)[_-][A-Za-z0-9_-]{12,}\b/gi
  },
  {
    category: "credential",
    expression:
      /(?<![A-Za-z0-9])(?:password|passwd|passphrase|secret|token|api[_-]?key)["']?\s*[:=]\s*["']?[^\s"'&,;]{3,}/gi
  },
  {
    category: "email-address",
    expression: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
  },
  {
    category: "card-number",
    expression: /\b\d(?:[ -]?\d){12,18}\b/g,
    accept: (match) => {
      const digits = match.replaceAll(/\D/g, "");
      return cardPrefixes.test(digits) && passesLuhn(digits);
    }
  },
  {
    category: "phone-number",
    expression: /(?<![\w+])\+[1-9]\d{0,2}(?:[ .-]?\d){6,13}(?!\d)|(?<!\d)0[2-478](?:[ -]?\d){8}(?!\d)/g
  },
  {
    category: "url-query",
    expression: /https?:\/\/[^\s?]+\?[^\s]+/gi
  }
];

const findingScopes = new Set(["event", "title", "environment"]);
const findingParts = new Set(["value", "key"]);

function displayPath(root, segments) {
  return `${root}${segments
    .map((segment) =>
      typeof segment === "number" ? `[${segment}]` : `[${JSON.stringify(segment)}]`
    )
    .join("")}`;
}

function stringEntries(value, pathSegments = []) {
  if (typeof value === "string") {
    return [{ part: "value", pathSegments: [...pathSegments], value }];
  }
  if (Array.isArray(value)) {
    return value.flatMap((entry, index) =>
      stringEntries(entry, [...pathSegments, index])
    );
  }
  if (isRecord(value)) {
    return Object.entries(value).flatMap(([key, entry]) => [
      { part: "key", pathSegments: [...pathSegments, key], value: key },
      ...stringEntries(entry, [...pathSegments, key])
    ]);
  }
  return [];
}

function maskedPreview(value, start, length) {
  const before = value.slice(Math.max(0, start - 10), start);
  const after = value.slice(start + length, start + length + 10);
  return `${before}[sensitive ${length} chars]${after}`;
}

function scanTargets(session) {
  return [
    {
      scope: "title",
      id: "title",
      eventId: null,
      root: "title",
      entries: [{ part: "value", pathSegments: [], value: session.title }]
    },
    {
      scope: "environment",
      id: "environment",
      eventId: null,
      root: "environment",
      entries: stringEntries(session.environment)
    },
    ...session.events.map((event) => ({
      scope: "event",
      id: event.id,
      eventId: event.id,
      root: "payload",
      entries: stringEntries(event.payload)
    }))
  ];
}

export function scanSensitiveData(input) {
  const session = validateSession(input);
  const findings = [];
  for (const target of scanTargets(session)) {
    for (const entry of target.entries) {
      for (const pattern of patterns) {
        for (const match of entry.value.matchAll(pattern.expression)) {
          if (pattern.accept && !pattern.accept(match[0])) {
            continue;
          }
          const path = displayPath(target.root, entry.pathSegments);
          findings.push({
            id: `finding-${target.id}-${findings.length + 1}`,
            scope: target.scope,
            eventId: target.eventId,
            part: entry.part,
            path: entry.part === "key" ? `${path} (field name)` : path,
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

const REDACTED_FIELD = "[REDACTED-FIELD]";

function redactKeyAtPath(value, segments, replacer) {
  let parent = value;
  for (const segment of segments.slice(0, -1)) {
    parent = isRecord(parent) || Array.isArray(parent) ? parent[segment] : undefined;
  }
  const finalKey = segments.at(-1);
  if (typeof finalKey !== "string" || !isRecord(parent) || !Object.hasOwn(parent, finalKey)) {
    throw new DiagnosticError(
      "Redaction path must resolve to a payload field name",
      "findings.pathSegments",
      "INVALID_FINDING"
    );
  }
  // The replacer still checks each finding against the original name, but the
  // new name keeps none of it: a placeholder such as "[REDACTED:api-key]"
  // would itself trip the capture boundary, so fields get a numbered marker.
  replacer(finalKey);
  let renamed = REDACTED_FIELD;
  for (let suffix = 2; Object.hasOwn(parent, renamed); suffix += 1) {
    renamed = `${REDACTED_FIELD} ${suffix}`;
  }
  const entries = Object.entries(parent);
  for (const [key] of entries) {
    delete parent[key];
  }
  for (const [key, entry] of entries) {
    Object.defineProperty(parent, key === finalKey ? renamed : key, {
      value: entry,
      enumerable: true,
      writable: true,
      configurable: true
    });
  }
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
  const groups = new Map();
  for (const [index, finding] of findings.entries()) {
    if (!accepted.has(finding.id)) {
      continue;
    }
    const scope = finding.scope ?? "event";
    const part = finding.part ?? "value";
    if (!findingScopes.has(scope) || !findingParts.has(part)) {
      throw new DiagnosticError(
        "Finding scope must be event, title or environment, and part must be value or key",
        `findings.${index}`,
        "INVALID_FINDING"
      );
    }
    if (
      !Array.isArray(finding.pathSegments) ||
      finding.pathSegments.some(
        (segment) => typeof segment !== "string" && !Number.isInteger(segment)
      ) ||
      (scope === "title" && (finding.pathSegments.length > 0 || part !== "value"))
    ) {
      throw new DiagnosticError(
        "Finding pathSegments must contain string or integer segments",
        `findings.${index}.pathSegments`,
        "INVALID_FINDING"
      );
    }
    const groupKey = JSON.stringify([scope, finding.eventId, part, finding.pathSegments]);
    const group = groups.get(groupKey) ?? {
      scope,
      eventId: finding.eventId,
      part,
      pathSegments: [...finding.pathSegments],
      findings: []
    };
    group.findings.push({ finding, index });
    groups.set(groupKey, group);
  }
  const eventsById = new Map(reviewed.events.map((event) => [event.id, event]));
  // Values are redacted before any field is renamed, and deeper fields are
  // renamed before their parents, so every path still resolves when used.
  const ordered = [...groups.values()].sort(
    (left, right) =>
      (left.part === "key") - (right.part === "key") ||
      right.pathSegments.length - left.pathSegments.length
  );
  for (const group of ordered) {
    const redact = (text) => redactSpans(text, group.findings);
    if (group.scope === "title") {
      reviewed.title = redact(reviewed.title);
      continue;
    }
    const container =
      group.scope === "environment"
        ? reviewed.environment
        : eventsById.get(group.eventId)?.payload;
    if (container === undefined) {
      continue;
    }
    if (group.part === "key") {
      redactKeyAtPath(container, group.pathSegments, redact);
    } else {
      replaceAtPath(container, group.pathSegments, redact);
    }
  }
  return validateSession(reviewed);
}

export function describeEvent(event) {
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
      `- ${event.atMs.toFixed(0)} ms — ${markdownSafe(describeEvent(event))}`
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
