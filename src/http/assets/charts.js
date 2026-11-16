(() => {
  "use strict";

  // Delta between absolute WireGuard counters; on reset treat the sample as the delta.
  const counterDeltas = (points, field) => {
    const out = [];
    for (let i = 1; i < points.length; i += 1) {
      const prev = points[i - 1][field] ?? 0;
      const cur = points[i][field] ?? 0;
      out.push(cur >= prev ? cur - prev : cur);
    }
    return out;
  };

  const themeColor = (name, fallback) => {
    const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return value || fallback;
  };

  const drawSeries = (ctx, values, color, width, height, pad) => {
    const max = Math.max(1, ...values);
    const step = values.length > 1 ? (width - pad * 2) / (values.length - 1) : 0;
    ctx.beginPath();
    values.forEach((v, i) => {
      const x = pad + i * step;
      const y = height - pad - (v / max) * (height - pad * 2);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.lineJoin = "round";
    ctx.stroke();
  };

  const render = (host, points) => {
    host.replaceChildren();
    if (!points || points.length < 2) {
      const empty = document.createElement("span");
      empty.className = "sparkline-empty";
      empty.textContent = points && points.length === 1 ? "Collecting samples…" : "No history yet";
      empty.setAttribute("aria-hidden", "true");
      host.append(empty);
      return;
    }
    const width = 96;
    const height = 28;
    const pad = 2;
    const canvas = document.createElement("canvas");
    canvas.className = "sparkline-canvas";
    canvas.width = width;
    canvas.height = height;
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", "Recent download and upload traffic");
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      const empty = document.createElement("span");
      empty.className = "sparkline-empty";
      empty.textContent = "Chart unavailable";
      host.append(empty);
      return;
    }
    drawSeries(ctx, counterDeltas(points, "rx_bytes"), themeColor("--accent", "#1f5fa9"), width, height, pad);
    drawSeries(ctx, counterDeltas(points, "tx_bytes"), themeColor("--ok", "#1b5e3f"), width, height, pad);
    host.append(canvas);
  };

  globalThis.wgBasicSparkline = { counterDeltas, render };
})();