import {
  DiagnosticRecorder,
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
  reviewStatus: document.querySelector("#review-status"),
  findings: document.querySelector("#finding-list"),
  streamRemoval: document.querySelector("#stream-removal"),
  json: document.querySelector("#json-button"),
  markdown: document.querySelector("#markdown-button"),
  output: document.querySelector("#report-output")
};

let recorder;
let draft;
let reviewed;
let findings = [];
let reviewPolicy = mergeReviewPolicy();
let indicatorTimer;

function nextPaint() {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
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
      `Could not complete the action: ${error instanceof Error ? error.message : String(error)}. The draft remains available.`,
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
  elements.start.disabled = active;
  elements.sample.disabled = active;
  elements.pause.disabled = !active;
  elements.pause.textContent = paused ? "Resume" : "Pause";
  elements.stop.disabled = !active;
  for (const control of [
    elements.click,
    elements.network,
    elements.console,
    elements.markerText,
    elements.marker
  ]) {
    control.disabled = !active || paused;
  }
}

function startIndicator() {
  clearInterval(indicatorTimer);
  elements.indicator.dataset.active = "true";
  indicatorTimer = setInterval(() => {
    const state = recorder?.state;
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

function renderTimeline(session) {
  const events = buildTimeline(session);
  elements.eventCount.textContent = `${events.length} event${events.length === 1 ? "" : "s"}`;
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
      const removeLabel = document.createElement("label");
      removeLabel.className = "remove-event";
      const remove = document.createElement("input");
      remove.type = "checkbox";
      remove.dataset.removeEvent = event.id;
      removeLabel.append(remove, " Remove from export");
      item.append(time, stream, summary, removeLabel);
      return item;
    })
  );
}

function prepareDraft(session) {
  draft = validateSession(session);
  reviewed = undefined;
  findings = [];
  reviewPolicy = mergeReviewPolicy();
  elements.findings.replaceChildren();
  elements.output.value = "";
  elements.scan.disabled = false;
  elements.applyReview.disabled = true;
  elements.json.disabled = true;
  elements.markdown.disabled = true;
  renderTimeline(draft);
  renderStreamRemoval();
}

function renderStreamRemoval() {
  const legend = elements.streamRemoval.querySelector("legend");
  elements.streamRemoval.replaceChildren(legend);
  for (const stream of draft.streams) {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.value = stream;
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
  elements.findings.replaceChildren(
    ...findings.map((finding) => {
      const label = document.createElement("label");
      const input = document.createElement("input");
      input.type = "checkbox";
      input.checked = true;
      input.value = finding.id;
      const copy = document.createElement("span");
      const title = document.createElement("strong");
      title.textContent = `${finding.category} in ${findingLocation(finding)}`;
      const preview = document.createElement("small");
      preview.textContent = finding.preview;
      copy.append(title, preview);
      label.append(input, copy);
      return label;
    })
  );
}

elements.start.addEventListener("click", async () => {
  elements.start.disabled = true;
  try {
    await withLoading("Starting the local recorder", async () => {
      await new Promise((resolve) => setTimeout(resolve, 120));
      recorder = new DiagnosticRecorder();
      recorder.start({
        confirmed: elements.confirm.checked,
        streams: selectedStreams(),
        environment: {
          browser: navigator.userAgent,
          viewport: `${window.innerWidth}×${window.innerHeight}`,
          platform: navigator.platform || "browser"
        }
      });
      draft = undefined;
      reviewed = undefined;
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

elements.stop.addEventListener("click", async () => {
  elements.stop.disabled = true;
  try {
    await withLoading("Finalising the synchronised event index", async () => {
      await nextPaint();
      prepareDraft(recorder.stop());
      setCaptureControls(false);
      stopIndicator(`Recording stopped at ${elapsedText()}. The local draft is ready for review.`);
    });
    setReviewStatus("Draft ready. Scan and inspect every stream before export.", false);
  } catch {
    elements.stop.disabled = false;
  }
});

elements.click.addEventListener("click", () => {
  recorder.append("interactions", "click", {
    target: "Place order button",
    category: "button",
    valueCaptured: false
  });
});

elements.network.addEventListener("click", () => {
  recorder.append("network", "request-complete", {
    url: "https://api.example.test/checkout?customer=not-captured",
    method: "POST",
    status: 422,
    durationMs: 2488,
    sizeBytes: 612,
    headers: { authorisation: "not captured" },
    body: "not captured"
  });
});

elements.console.addEventListener("click", () => {
  recorder.append("console", "error", {
    level: "error",
    message: "Validation failed for reporter@example.test with Bearer local_fixture_token_123456789"
  });
});

elements.marker.addEventListener("click", () => {
  recorder.marker(elements.markerText.value || "Unlabelled marker");
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
      elements.applyReview.disabled = false;
    });
    setReviewStatus(
      `Scan complete: ${findings.length} finding${findings.length === 1 ? "" : "s"}. Checked findings will be redacted.`,
      false
    );
  } catch {
    // withLoading has supplied a recoverable message.
  } finally {
    elements.scan.disabled = false;
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
      reviewPolicy = mergeReviewPolicy(reviewPolicy, {
        redactFindingIds,
        removeEventIds,
        removeStreams
      });
      reviewed = applyReview(draft, {
        findings,
        ...reviewPolicy
      });
      renderTimeline(reviewed);
      elements.json.disabled = false;
      elements.markdown.disabled = false;
      elements.output.value = "";
    });
    setReviewStatus("Derived report copy ready. The original local draft remains unchanged.", false);
  } catch {
    // withLoading has supplied a recoverable message.
  } finally {
    elements.applyReview.disabled = false;
  }
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
    elements.json.disabled = false;
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
    elements.markdown.disabled = false;
  }
});

setCaptureControls(false);
