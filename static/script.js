const targetInput = document.getElementById("targetInput");
const capInput = document.getElementById("capInput");
const runBruteBtn = document.getElementById("runBruteBtn");
const bruteProgress = document.getElementById("bruteProgress");
const bruteMetrics = document.getElementById("bruteMetrics");
const bruteLog = document.getElementById("bruteLog");
const bruteChart = document.getElementById("bruteChart");
const bruteChartMeta = document.getElementById("bruteChartMeta");

const payloadInput = document.getElementById("payloadInput");
const usernameInput = document.getElementById("usernameInput");
const passwordInput = document.getElementById("passwordInput");
const runSqliBtn = document.getElementById("runSqliBtn");
const sqliResult = document.getElementById("sqliResult");
const sqliChart = document.getElementById("sqliChart");
const sqliChartMeta = document.getElementById("sqliChartMeta");

const explainText = document.getElementById("explainText");
const mitigationList = document.getElementById("mitigationList");

let bruteTimer = null;
let sqliAnimFrame = null;

function formatNum(value) {
  return Number(value).toLocaleString();
}

function setMitigations(items) {
  mitigationList.innerHTML = "";
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    mitigationList.appendChild(li);
  });
}

function appendLog(line) {
  bruteLog.textContent += `\n${line}`;
  bruteLog.scrollTop = bruteLog.scrollHeight;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getCtx(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(rect.height * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, width: rect.width, height: rect.height };
}

function drawGrid(ctx, width, height, lines = 5) {
  ctx.clearRect(0, 0, width, height);
  ctx.lineWidth = 1;
  ctx.strokeStyle = "rgba(84, 255, 194, 0.14)";
  for (let i = 1; i <= lines; i += 1) {
    const y = (height / (lines + 1)) * i;
    ctx.beginPath();
    ctx.moveTo(12, y);
    ctx.lineTo(width - 12, y);
    ctx.stroke();
  }
}

function drawBruteChart(points, maxY = 1) {
  const { ctx, width, height } = getCtx(bruteChart);
  drawGrid(ctx, width, height, 5);

  if (!points.length) {
    ctx.fillStyle = "rgba(198, 255, 240, 0.7)";
    ctx.font = "12px JetBrains Mono, monospace";
    ctx.fillText("Run brute force to see live attempt curve", 16, height / 2);
    return;
  }

  const left = 16;
  const right = width - 16;
  const top = 14;
  const bottom = height - 16;
  const chartWidth = right - left;
  const chartHeight = bottom - top;

  const stepX = points.length > 1 ? chartWidth / (points.length - 1) : 0;

  ctx.beginPath();
  points.forEach((value, idx) => {
    const x = left + stepX * idx;
    const y = bottom - (Math.max(value, 0) / Math.max(maxY, 1)) * chartHeight;
    if (idx === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });

  ctx.lineWidth = 2;
  ctx.strokeStyle = "#54ffc2";
  ctx.shadowColor = "rgba(84, 255, 194, 0.45)";
  ctx.shadowBlur = 8;
  ctx.stroke();
  ctx.shadowBlur = 0;

  const lastValue = points[points.length - 1];
  const lastX = left + stepX * (points.length - 1);
  const lastY = bottom - (Math.max(lastValue, 0) / Math.max(maxY, 1)) * chartHeight;

  ctx.fillStyle = "#35d1ff";
  ctx.beginPath();
  ctx.arc(lastX, lastY, 4, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "rgba(198, 255, 240, 0.85)";
  ctx.font = "12px JetBrains Mono, monospace";
  ctx.fillText(`last: ${formatNum(lastValue)} attempts`, 16, 16);
}

function drawSqliChart(unsafeScore, safeScore) {
  const { ctx, width, height } = getCtx(sqliChart);
  drawGrid(ctx, width, height, 4);

  const maxScore = 100;
  const left = 24;
  const top = 30;
  const availableWidth = width - 2 * left;
  const barGap = 16;
  const barHeight = 40;

  function barY(index) {
    return top + index * (barHeight + barGap);
  }

  function drawBar(y, value, label, fill, textColor) {
    const w = Math.max(0, Math.min(availableWidth, (value / maxScore) * availableWidth));

    ctx.fillStyle = "rgba(10, 18, 32, 0.9)";
    ctx.fillRect(left, y, availableWidth, barHeight);

    ctx.fillStyle = fill;
    ctx.fillRect(left, y, w, barHeight);

    ctx.strokeStyle = "rgba(84, 255, 194, 0.22)";
    ctx.strokeRect(left, y, availableWidth, barHeight);

    ctx.fillStyle = "#c6fff0";
    ctx.font = "12px JetBrains Mono, monospace";
    ctx.fillText(label, left + 8, y + 16);

    ctx.fillStyle = textColor;
    ctx.font = "14px JetBrains Mono, monospace";
    ctx.fillText(`${Math.round(value)}%`, left + 8, y + 32);
  }

  drawBar(barY(0), unsafeScore, "Unsafe path", "rgba(255, 95, 143, 0.85)", "#ffd7e4");
  drawBar(barY(1), safeScore, "Safe path", "rgba(84, 255, 194, 0.8)", "#ccffef");
}

function resetBruteChart() {
  drawBruteChart([]);
  bruteChartMeta.textContent = "Idle";
}

function resetSqliChart() {
  drawSqliChart(0, 0);
  sqliChartMeta.textContent = "Idle";
}

function stopBruteTimer() {
  if (bruteTimer !== null) {
    clearInterval(bruteTimer);
    bruteTimer = null;
  }
}

function runBruteChartAnimation(data) {
  return new Promise((resolve) => {
    const series = [];
    let idx = 0;

    stopBruteTimer();
    bruteTimer = setInterval(() => {
      if (idx >= data.logs.length) {
        stopBruteTimer();
        bruteChartMeta.textContent = data.cracked
          ? "Simulation complete: target cracked"
          : "Simulation complete: cap reached";
        resolve();
        return;
      }

      const log = data.logs[idx];
      const pct = Math.round(((idx + 1) / data.logs.length) * 100);
      bruteProgress.style.width = `${pct}%`;

      series.push(log.attempt);
      drawBruteChart(series, data.attempts_used || 1);
      bruteChartMeta.textContent = `${pct}% complete`;

      appendLog(
        `[attempt ${formatNum(log.attempt)}] candidate=${log.candidate} | ${log.status}`
      );

      idx += 1;
    }, 220);
  });
}

function scoreFromClassification(classification, recordsExposed) {
  if (classification === "destructive_intent") {
    return 98;
  }
  if (classification === "auth_bypass") {
    return 92;
  }
  if (classification === "union_leak") {
    return 84;
  }
  if (recordsExposed > 1) {
    return 65;
  }
  return recordsExposed === 1 ? 18 : 8;
}

function animateSqliBars(targetUnsafe, targetSafe) {
  if (sqliAnimFrame !== null) {
    cancelAnimationFrame(sqliAnimFrame);
  }

  return new Promise((resolve) => {
    const duration = 700;
    const start = performance.now();

    function step(ts) {
      const elapsed = ts - start;
      const t = Math.min(elapsed / duration, 1);
      const ease = 1 - (1 - t) * (1 - t);

      drawSqliChart(targetUnsafe * ease, targetSafe * ease);
      sqliChartMeta.textContent = `Unsafe ${Math.round(targetUnsafe * ease)}% | Safe ${Math.round(
        targetSafe * ease
      )}%`;

      if (t < 1) {
        sqliAnimFrame = requestAnimationFrame(step);
      } else {
        sqliChartMeta.textContent = `Final score: Unsafe ${Math.round(
          targetUnsafe
        )}% vs Safe ${Math.round(targetSafe)}%`;
        resolve();
      }
    }

    sqliAnimFrame = requestAnimationFrame(step);
  });
}

async function runBruteForceSimulation() {
  runBruteBtn.disabled = true;
  runBruteBtn.textContent = "Running...";
  bruteLog.textContent = "[system] launching brute force simulation...";
  bruteProgress.style.width = "0%";
  resetBruteChart();

  try {
    const response = await fetch("/api/bruteforce", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: targetInput.value,
        attempt_cap: Number(capInput.value),
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    bruteMetrics.innerHTML = `
      <div>Attempts: ${formatNum(data.attempts_used)}</div>
      <div>Search Space: ${formatNum(data.search_space)}</div>
      <div>Status: ${data.cracked ? "Cracked" : "Uncracked"}</div>
    `;

    await runBruteChartAnimation(data);

    appendLog(`[summary] est time=${data.estimated_seconds.toFixed(2)}s | target=${data.target}`);

    explainText.textContent = data.explanation;
    setMitigations(data.mitigations);
  } catch (error) {
    appendLog(`[error] ${error.message}`);
    bruteChartMeta.textContent = "Error";
  } finally {
    runBruteBtn.disabled = false;
    runBruteBtn.textContent = "Run Brute Force";
  }
}

function resolvePayloadDefault(key) {
  if (key === "auth_bypass") return "' OR '1'='1' --";
  if (key === "union_dump") return "' UNION SELECT username, password FROM users --";
  if (key === "destructive") return "'; DROP TABLE users; --";
  return "normal input";
}

async function runSqliSimulation() {
  runSqliBtn.disabled = true;
  runSqliBtn.textContent = "Running...";

  try {
    const response = await fetch("/api/sqli", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        payload_key: payloadInput.value,
        username: usernameInput.value,
        password: passwordInput.value,
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    sqliResult.innerHTML = `
      <div class="query-card">
        <h3>Unsafe Query (${escapeHtml(data.unsafe_outcome.label)})</h3>
        <code>${escapeHtml(data.unsafe_query)}</code>
        <p>Records exposed: ${escapeHtml(data.unsafe_outcome.records_exposed)}</p>
        <p>${escapeHtml(data.unsafe_outcome.impact)}</p>
      </div>
      <div class="query-card safe">
        <h3>Safe Query (${escapeHtml(data.safe_outcome.label)})</h3>
        <code>${escapeHtml(data.safe_query)}</code>
        <p>Records exposed: ${escapeHtml(data.safe_outcome.records_exposed)}</p>
        <p>${escapeHtml(data.safe_outcome.impact)}</p>
      </div>
    `;

    const unsafeScore = scoreFromClassification(
      data.classification,
      Number(data.unsafe_outcome.records_exposed)
    );
    const safeScore = Math.max(2, Number(data.safe_outcome.records_exposed) * 8);
    await animateSqliBars(unsafeScore, safeScore);

    explainText.textContent =
      "SQL injection happens when user input is concatenated into SQL text. Prepared statements separate code from data and prevent this class of bug.";
    setMitigations(data.mitigations);
  } catch (error) {
    explainText.textContent = `Simulation error: ${error.message}`;
    sqliChartMeta.textContent = "Error";
  } finally {
    runSqliBtn.disabled = false;
    runSqliBtn.textContent = "Run SQL Injection";
  }
}

payloadInput.addEventListener("change", () => {
  passwordInput.value = resolvePayloadDefault(payloadInput.value);
});

window.addEventListener("resize", () => {
  drawBruteChart([]);
  drawSqliChart(0, 0);
});

runBruteBtn.addEventListener("click", runBruteForceSimulation);
runSqliBtn.addEventListener("click", runSqliSimulation);

resetBruteChart();
resetSqliChart();
