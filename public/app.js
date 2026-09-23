import {
  DiagnosticRecorder,
  MAX_SESSION_DURATION_MS,
  applyReview,
  buildTimeline,
  createMarkdownReport,
  createPortableReport,
  describeEvent,
  mergeReviewPolicy,
  scanSensitiveData,
  validateReport,
  validateSession
} from "/src/diagnostics.js";

const elements = {
  streams: document.querySelector("#stream-fields"),
  confirm: document.querySelector("#confirm-streams"),
  start: document.querySelector("#start-button"),
  pause: document.querySelector("#pause-button"),
  stop: document.querySelector("#stop-button"),
  sample: document.querySelector("#sample-button"),
  indicator: document.querySelector("#recording-indicator"),
  click: document.querySelector("#add-click"),
  network: document.querySelector("#add-network"),
  console: document.querySelector("#add-console"),
  markerText: document.querySelector("#marker-text"),
  marker: document.querySelector("#add-marker"),
  timeline: document.querySelector("#timeline"),
  eventCount: document.querySelector("#event-count"),
  scan: document.querySelector("#scan-button"),
  applyReview: document.querySelector("#apply-review"),
  resetReview: document.querySelector("#reset-review"),
  reviewStatus: document.querySelector("#review-status"),
  findings: document.querySelector("#finding-list"),
  streamRemoval: document.querySelector("#stream-removal"),
  json: document.querySelector("#json-button"),
  markdown: document.querySelector("#markdown-button"),
  output: document.querySelector("#report-output")
};

const streamControls = [
  [elements.click, "interactions"],
  [elements.network, "network"],
  [elements.console, "console"],
  [elements.markerText, "markers"],
  [elements.marker, "markers"]
];

let recorder;
let draft;
let reviewed;
let findings = [];
let reviewPolicy = mergeReviewPolicy();
let indicatorTimer;

function nextPaint() {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function plural(count, noun) {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

function setReviewStatus(message, loading = false) {
  elements.reviewStatus.dataset.loading = String(loading);
  elements.reviewStatus.textContent = loading ? `Loading: ${message}` : message;
}

async function withLoading(label, operation) {
  setReviewStatus(label, true);
  await nextPaint();
  try {
    return await operation();
  } catch (error) {
    setReviewStatus(
      `Could not complete the action: ${errorMessage(error)}.${draft ? " The draft remains available." : ""}`,
      false
    );
    throw error;
  }
}

function selectedStreams() {
  return [...elements.streams.querySelectorAll("input:checked")].map((input) => input.value);
}

function elapsedText() {
  const snapshot = recorder?.snapshot();
  return snapshot ? `${(snapshot.durationMs / 1000).toFixed(1)} seconds` : "0.0 seconds";
}

function setCaptureControls(active, paused = false) {
  const enabledStreams = active ? recorder.snapshot().streams : [];
  elements.start.disabled = active;
  elements.sample.disabled = active;
  elements.streams.disabled = active;
  elements.confirm.disabled = active;
  elements.pause.disabled = !active;
  elements.pause.textContent = paused ? "Resume" : "Pause";
  elements.stop.disabled = !active;
  for (const [control, stream] of streamControls) {
    control.disabled =
      !active || paused || (stream !== "markers" && !enabledStreams.includes(stream));
  }
}

function startIndicator() {
  clearInterval(indicatorTimer);
  elements.indicator.dataset.active = "true";
  indicatorTimer = setInterval(() => {
    const state = recorder?.state;
    if (state === "recording" && recorder.snapshot().durationMs >= MAX_SESSION_DURATION_MS) {
      clearInterval(indicatorTimer);
      finishRecording("Recording reached its one-hour limit and stopped");
      return;
    }
    elements.indicator.textContent =
      state === "paused"
        ? `Recording paused at ${elapsedText()}. Resume or stop to continue.`
        : `Recording active: ${elapsedText()}. Stop when the reproduction is complete.`;
  }, 100);
}

function stopIndicator(message) {
  clearInterval(indicatorTimer);
  elements.indicator.dataset.active = "false";
  elements.indicator.textContent = message;
}

function renderEmptyTimeline(message) {
  const item = document.createElement("li");
  item.className = "empty-state";
  item.textContent = message;
  elements.timeline.replaceChildren(item);
  elements.eventCount.textContent = plural(0, "event");
}

function renderTimeline(session, { removable = true } = {}) {
  const events = buildTimeline(session);
  if (events.length === 0) {
    renderEmptyTimeline(
      removable ? "No events in this session." : "Events appear here as they are recorded."
    );
    return;
  }
  elements.eventCount.textContent = plural(events.length, "event");
  elements.timeline.replaceChildren(
    ...events.map((event) => {
      const item = document.createElement("li");
      item.dataset.eventId = event.id;
      const time = document.createElement("time");
      time.textContent = `${event.atMs.toFixed(0)} ms`;
      const stream = document.createElement("strong");
      stream.textContent = event.stream;
      const summary = document.createElement("span");
      summary.textContent = describeEvent(event);
      item.append(time, stream, summary);
      if (removable) {
        const removeLabel = document.createElement("label");
        removeLabel.className = "remove-event";
        const remove = document.createElement("input");
        remove.type = "checkbox";
        remove.dataset.removeEvent = event.id;
        removeLabel.append(remove, " Remove from export");
        item.append(removeLabel);
      }
      return item;
    })
  );
}

function setReviewControls() {
  elements.scan.disabled = !draft;
  elements.applyReview.disabled = !draft || elements.findings.childElementCount === 0;
  elements.resetReview.disabled = !reviewed;
  elements.json.disabled = !reviewed;
  elements.markdown.disabled = !reviewed;
}

function clearDraft(timelineMessage) {
  draft = undefined;
  reviewed = undefined;
  findings = [];
  reviewPolicy = mergeReviewPolicy();
  elements.findings.replaceChildren();
  elements.output.value = "";
  renderEmptyTimeline(timelineMessage);
  renderStreamRemoval();
  setReviewControls();
}

function prepareDraft(session) {
  const next = validateSession(session);
  clearDraft("");
  draft = next;
  renderTimeline(draft);
  renderStreamRemoval();
  setReviewControls();
}

function draftStreams() {
  // Markers are always recordable, so they may appear in events without
  // being listed among the streams chosen before recording.
  return [...new Set([...draft.streams, ...draft.events.map((event) => event.stream)])];
}

function renderStreamRemoval() {
  const legend = elements.streamRemoval.querySelector("legend");
  elements.streamRemoval.replaceChildren(legend);
  if (!draft) {
    elements.streamRemoval.disabled = true;
    return;
  }
  const removed = new Set(reviewPolicy.removeStreams);
  for (const stream of draftStreams()) {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = stream;
    input.checked = removed.has(stream);
    input.disabled = removed.has(stream);
    label.append(input, ` Remove ${stream}`);
    elements.streamRemoval.append(label);
  }
  elements.streamRemoval.disabled = false;
}

function findingLocation(finding) {
  const place =
    finding.scope === "title"
      ? "the report title"
      : finding.scope === "environment"
        ? "environment details"
        : finding.eventId;
  return finding.part === "key" ? `a field name in ${place}` : place;
}

function renderFindings() {
  if (findings.length === 0) {
    const message = document.createElement("p");
    message.textContent = "No configured sensitive patterns were found. Manual review is still required.";
    elements.findings.replaceChildren(message);
    return;
  }
  const redacted = new Set(reviewPolicy.redactFindingIds);
  elements.findings.replaceChildren(
    ...findings.map((finding) => {
      const label = document.createElement("label");
      const input = document.createElement("input");
      input.type = "checkbox";
      input.value = finding.id;
      // Once a review is applied the list mirrors the report copy: redactions
      // already made stay locked until the review is started again.
      input.checked = reviewed ? redacted.has(finding.id) : true;
      input.disabled = redacted.has(finding.id);
      const copy = document.createElement("span");
      const title = document.createElement("strong");
      title.textContent = `${finding.category} in ${findingLocation(finding)}`;
      const preview = document.createElement("small");
      preview.textContent = finding.preview;
      copy.append(title, preview);
      if (input.disabled) {
        const note = document.createElement("em");
        note.textContent = "Redacted in the report copy";
        copy.append(note);
      }
      label.append(input, copy);
      return label;
    })
  );
}

function record(append) {
  try {
    append();
    renderTimeline(recorder.snapshot(), { removable: false });
  } catch (error) {
    setReviewStatus(`Could not record the event: ${errorMessage(error)}.`, false);
  }
}

async function finishRecording(reason) {
  elements.stop.disabled = true;
  try {
    await withLoading("Finalising the synchronised event index", async () => {
      await nextPaint();
      prepareDraft(recorder.stop());
      setCaptureControls(false);
      elements.confirm.checked = false;
      stopIndicator(`${reason} at ${elapsedText()}. The local draft is ready for review.`);
    });
    setReviewStatus("Draft ready. Scan and inspect every stream before export.", false);
  } catch {
    elements.stop.disabled = false;
  }
}

elements.streams.addEventListener("change", () => {
  // Confirmation covers one specific selection of streams.
  elements.confirm.checked = false;
});

elements.start.addEventListener("click", async () => {
  elements.start.disabled = true;
  try {
    await withLoading("Starting the local recorder", async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));
      const next = new DiagnosticRecorder();
      next.start({
        confirmed: elements.confirm.checked,
        streams: selectedStreams(),
        environment: {
          browser: navigator.userAgent,
          viewport: `${window.innerWidth}×${window.innerHeight}`,
          platform: navigator.platform || "browser"
        }
      });
      recorder = next;
      clearDraft("Events appear here as they are recorded.");
      setCaptureControls(true);
      startIndicator();
    });
    setReviewStatus("Recorder active. Add only deliberate local diagnostic examples.", false);
  } catch {
    elements.start.disabled = false;
  }
});

elements.pause.addEventListener("click", () => {
  if (recorder.state === "recording") {
    recorder.pause();
    setCaptureControls(true, true);
  } else {
    recorder.resume();
    setCaptureControls(true, false);
  }
});

elements.stop.addEventListener("click", () => {
  finishRecording("Recording stopped");
});

elements.click.addEventListener("click", () => {
  record(() =>
    recorder.append("interactions", "click", {
      target: "Place order button",
      category: "button",
      valueCaptured: false
    })
  );
});

elements.network.addEventListener("click", () => {
  record(() =>
    recorder.append("network", "request-complete", {
      url: "https://api.example.test/checkout?customer=not-captured",
      method: "POST",
      status: 422,
      durationMs: 2488,
      sizeBytes: 612,
      headers: { authorisation: "not captured" },
      body: "not captured"
    })
  );
});

elements.console.addEventListener("click", () => {
  record(() =>
    recorder.append("console", "error", {
      level: "error",
      message: "Validation failed for reporter@example.test with Bearer local_fixture_token_123456789"
    })
  );
});

elements.marker.addEventListener("click", () => {
  record(() => recorder.marker(elements.markerText.value || "Unlabelled marker"));
});

elements.sample.addEventListener("click", async () => {
  elements.sample.disabled = true;
  try {
    await withLoading("Importing and validating the checkout fixture", async () => {
      const response = await fetch("/examples/checkout-session.json");
      if (!response.ok) {
        throw new Error(`Fixture request returned ${response.status}`);
      }
      prepareDraft(await response.json());
      stopIndicator("Imported checkout fixture ready for review.");
    });
    setReviewStatus("Fixture imported. Run the sensitive-data scan before export.", false);
  } catch {
    // withLoading has supplied a recoverable message.
  } finally {
    elements.sample.disabled = false;
  }
});

elements.scan.addEventListener("click", async () => {
  elements.scan.disabled = true;
  try {
    await withLoading("Scanning diagnostic strings for sensitive patterns", async () => {
      await nextPaint();
      findings = scanSensitiveData(draft);
      renderFindings();
    });
    setReviewStatus(
      `Scan complete: ${plural(findings.length, "finding")}. Checked findings will be redacted.`,
      false
    );
  } catch {
    // withLoading has supplied a recoverable message.
  } finally {
    setReviewControls();
  }
});

elements.applyReview.addEventListener("click", async () => {
  elements.applyReview.disabled = true;
  try {
    await withLoading("Applying removals and redactions to a derived copy", async () => {
      await nextPaint();
      const redactFindingIds = [
        ...elements.findings.querySelectorAll("input:checked")
      ].map((input) => input.value);
      const removeEventIds = [
        ...elements.timeline.querySelectorAll("[data-remove-event]:checked")
      ].map((input) => input.dataset.removeEvent);
      const removeStreams = [
        ...elements.streamRemoval.querySelectorAll("input:checked")
      ].map((input) => input.value);
      const nextPolicy = mergeReviewPolicy(reviewPolicy, {
        redactFindingIds,
        removeEventIds,
        removeStreams
      });
      reviewed = applyReview(draft, {
        findings,
        ...nextPolicy
      });
      reviewPolicy = nextPolicy;
      renderTimeline(reviewed);
      renderFindings();
      renderStreamRemoval();
      elements.output.value = "";
    });
    const removedEvents = draft.events.length - reviewed.events.length;
    setReviewStatus(
      `Derived report copy ready: ${plural(reviewPolicy.redactFindingIds.length, "redaction")}, ${plural(removedEvents, "event")} removed. The original local draft remains unchanged.`,
      false
    );
  } catch {
    // withLoading has supplied a recoverable message.
  } finally {
    setReviewControls();
  }
});

elements.resetReview.addEventListener("click", () => {
  reviewed = undefined;
  reviewPolicy = mergeReviewPolicy();
  elements.output.value = "";
  renderTimeline(draft);
  if (elements.findings.childElementCount > 0) {
    renderFindings();
  }
  renderStreamRemoval();
  setReviewControls();
  setReviewStatus("Review cleared. Every finding, event and stream is back in the draft.", false);
});

elements.json.addEventListener("click", async () => {
  elements.json.disabled = true;
  try {
    await withLoading("Building and validating the portable JSON report", async () => {
      await nextPaint();
      const report = createPortableReport(reviewed);
      validateReport(report);
      elements.output.value = JSON.stringify(report, null, 2);
    });
    setReviewStatus("JSON report prepared with its visible privacy manifest.", false);
  } catch {
    // withLoading has supplied a recoverable message.
  } finally {
    setReviewControls();
  }
});

elements.markdown.addEventListener("click", async () => {
  elements.markdown.disabled = true;
  try {
    await withLoading("Building the sanitised Markdown summary", async () => {
      await nextPaint();
      elements.output.value = createMarkdownReport(reviewed);
    });
    setReviewStatus("Markdown report prepared from the reviewed copy.", false);
  } catch {
    // withLoading has supplied a recoverable message.
  } finally {
    setReviewControls();
  }
});

setCaptureControls(false);
setReviewControls();
