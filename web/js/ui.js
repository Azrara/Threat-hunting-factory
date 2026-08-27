// DOM helpers, formatting and dependency free charts.

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "html") node.innerHTML = value;
    else if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === "string" || typeof child === "number" ? document.createTextNode(String(child)) : child);
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const SEVERITY_COLOURS = {
  critical: "#b4141e",
  high: "#da291c",
  medium: "#ed8b00",
  low: "#86bc25",
  info: "#75787b",
};
export const FAMILY_LABELS = {
  cti: "Threat intelligence",
  technique: "Technique",
  mathematical: "Mathematical",
};

export function formatNumber(value) {
  return Number(value || 0).toLocaleString("en-GB");
}

export function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let index = -1;
  let size = value;
  do {
    size /= 1024;
    index += 1;
  } while (size >= 1024 && index < units.length - 1);
  return `${size.toFixed(size >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

export function formatDate(value, withTime = true) {
  if (!value) return "not available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const options = withTime
    ? { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }
    : { day: "2-digit", month: "short", year: "numeric" };
  return date.toLocaleString("en-GB", options);
}

export function relativeTime(value) {
  if (!value) return "";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "";
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  if (seconds < 2592000) return `${Math.floor(seconds / 86400)} d ago`;
  return formatDate(value, false);
}

export function severityBadge(severity) {
  return el("span", { class: `sev sev-${severity || "info"}`, text: severity || "info" });
}

export function statusBadge(status) {
  const labels = { completed: "Completed", running: "Running", pending: "Queued", failed: "Failed" };
  return el("span", { class: `status status-${status}` }, [
    el("span", { class: "dot" }),
    el("span", { text: labels[status] || status }),
  ]);
}

export function riskClass(score) {
  if (score >= 75) return "risk-critical";
  if (score >= 50) return "risk-high";
  if (score >= 25) return "risk-medium";
  return "";
}

let toastHost = null;
export function toast(message, kind = "info") {
  if (!toastHost) {
    toastHost = el("div", { class: "toast-stack" });
    document.body.appendChild(toastHost);
  }
  const node = el("div", { class: `toast ${kind === "error" ? "error" : ""}`, text: message });
  toastHost.appendChild(node);
  setTimeout(() => {
    node.style.opacity = "0";
    node.style.transition = "opacity .25s";
    setTimeout(() => node.remove(), 260);
  }, kind === "error" ? 6000 : 3800);
}

export function emptyState(title, message, action) {
  return el("div", { class: "empty" }, [
    el("h3", { text: title }),
    el("p", { class: "muted", text: message }),
    action || null,
  ]);
}

export function spinner(label) {
  return el("div", { class: "run-panel" }, [
    el("div", { class: "spinner" }),
    label ? el("div", { class: "stage", text: label }) : null,
  ]);
}

// ---------------------------------------------------------------- charts

const NS = "http://www.w3.org/2000/svg";

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(NS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

export function donut(data, { size = 168, thickness = 22, centreLabel = "", centreValue = "" } = {}) {
  const entries = data.filter((item) => item.value > 0);
  const total = entries.reduce((sum, item) => sum + item.value, 0);
  const radius = (size - thickness) / 2;
  const centre = size / 2;
  const svg = svgEl("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}`, role: "img" });
  if (!total) {
    svg.appendChild(svgEl("circle", {
      cx: centre, cy: centre, r: radius, fill: "none", stroke: "#e6e6e4", "stroke-width": thickness,
    }));
  } else {
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    for (const item of entries) {
      const length = (item.value / total) * circumference;
      const arc = svgEl("circle", {
        cx: centre,
        cy: centre,
        r: radius,
        fill: "none",
        stroke: item.colour,
        "stroke-width": thickness,
        "stroke-dasharray": `${length} ${circumference - length}`,
        "stroke-dashoffset": -offset,
        transform: `rotate(-90 ${centre} ${centre})`,
      });
      const title = svgEl("title");
      title.textContent = `${item.name}: ${item.value}`;
      arc.appendChild(title);
      svg.appendChild(arc);
      offset += length;
    }
  }
  const value = svgEl("text", {
    x: centre, y: centre - 2, "text-anchor": "middle", "dominant-baseline": "middle",
    "font-size": "26", "font-weight": "700", fill: "#0f0f0f",
  });
  value.textContent = centreValue !== "" ? String(centreValue) : String(total);
  svg.appendChild(value);
  if (centreLabel) {
    const label = svgEl("text", {
      x: centre, y: centre + 20, "text-anchor": "middle", "font-size": "10",
      fill: "#75787b", "letter-spacing": "1.2",
    });
    label.textContent = centreLabel.toUpperCase();
    svg.appendChild(label);
  }
  return svg;
}

export function barList(items, { colour = "#86bc25", max = null } = {}) {
  const peak = max || Math.max(1, ...items.map((item) => item.value));
  return el("div", {}, items.map((item) =>
    el("div", { class: "bar-row" }, [
      el("div", { class: "name", title: item.name, text: item.name }),
      el("div", { class: "bar-track" }, [
        el("div", {
          class: "bar-fill",
          style: `width:${Math.max(2, (item.value / peak) * 100)}%;background:${item.colour || colour}`,
        }),
      ]),
      el("div", { class: "val", text: formatNumber(item.value) }),
    ])
  ));
}

export function timelineChart(points, { height = 150 } = {}) {
  const width = 640;
  const padding = { top: 12, right: 8, bottom: 26, left: 30 };
  const svg = svgEl("svg", {
    viewBox: `0 0 ${width} ${height}`, width: "100%", height, preserveAspectRatio: "none", role: "img",
  });
  if (!points.length) return svg;
  const peak = Math.max(1, ...points.map((point) => point.value));
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const step = plotWidth / points.length;
  const barWidth = Math.max(3, Math.min(28, step * 0.62));

  for (let index = 0; index <= 3; index += 1) {
    const y = padding.top + (plotHeight / 3) * index;
    svg.appendChild(svgEl("line", {
      x1: padding.left, x2: width - padding.right, y1: y, y2: y, stroke: "#eeeeec", "stroke-width": 1,
    }));
    const label = svgEl("text", {
      x: padding.left - 6, y: y + 3, "text-anchor": "end", "font-size": "9", fill: "#9a9a98",
    });
    label.textContent = String(Math.round(peak - (peak / 3) * index));
    svg.appendChild(label);
  }

  points.forEach((point, index) => {
    const barHeight = Math.max(2, (point.value / peak) * plotHeight);
    const x = padding.left + index * step + (step - barWidth) / 2;
    const y = padding.top + plotHeight - barHeight;
    const rect = svgEl("rect", {
      x, y, width: barWidth, height: barHeight, fill: point.colour || "#86bc25", rx: 2,
    });
    const title = svgEl("title");
    title.textContent = `${point.label}: ${point.value}`;
    rect.appendChild(title);
    svg.appendChild(rect);
    if (points.length <= 16 || index % Math.ceil(points.length / 10) === 0) {
      const label = svgEl("text", {
        x: x + barWidth / 2, y: height - 8, "text-anchor": "middle", "font-size": "9", fill: "#9a9a98",
      });
      label.textContent = point.shortLabel || point.label;
      svg.appendChild(label);
    }
  });
  return svg;
}

export function legend(items) {
  return el("div", { class: "chart-legend" }, items.map((item) =>
    el("div", { class: "legend-row" }, [
      el("span", { class: "swatch", style: `background:${item.colour}` }),
      el("span", { class: "name", text: item.name }),
      el("span", { class: "val", text: formatNumber(item.value) }),
    ])
  ));
}

export function icon(name) {
  const paths = {
    dashboard: "M3 3h7v8H3V3zm0 10h7v8H3v-8zm9 5h9v3h-9v-3zm0-15h9v13h-9V3z",
    target: "M12 2a10 10 0 100 20 10 10 0 000-20zm0 2a8 8 0 110 16 8 8 0 010-16zm0 2a6 6 0 100 12 6 6 0 000-12zm0 2a4 4 0 110 8 4 4 0 010-8zm0 2a2 2 0 100 4 2 2 0 000-4z",
    play: "M8 5v14l11-7L8 5z",
    list: "M4 6h16v2H4V6zm0 5h16v2H4v-2zm0 5h16v2H4v-2z",
    shield: "M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z",
    users: "M16 11a4 4 0 10-4-4 4 4 0 004 4zm-8 1a3 3 0 10-3-3 3 3 0 003 3zm0 2c-2.7 0-8 1.3-8 4v3h8v-3c0-1 .4-2 1.2-2.8A13 13 0 008 14zm8 0c-3 0-9 1.5-9 4.5V21h18v-2.5c0-3-6-4.5-9-4.5z",
    logout: "M10 17l1.4-1.4L8.8 13H20v-2H8.8l2.6-2.6L10 7l-5 5 5 5zM4 5h8V3H4a2 2 0 00-2 2v14a2 2 0 002 2h8v-2H4V5z",
  };
  const svg = svgEl("svg", { viewBox: "0 0 24 24", fill: "currentColor" });
  svg.appendChild(svgEl("path", { d: paths[name] || paths.list, "fill-rule": "evenodd", "clip-rule": "evenodd" }));
  return svg;
}
