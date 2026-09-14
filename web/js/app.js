// Application shell and hash router.

import { api, auth } from "./api.js";
import { clear, el, icon, toast } from "./ui.js";
import { renderAuth } from "./views/auth.js";
import { renderDashboard } from "./views/dashboard.js";
import { renderHypotheses } from "./views/hypotheses.js";
import { renderNewHunt } from "./views/newhunt.js";
import { renderHunts } from "./views/hunts.js";
import { renderReport } from "./views/report.js";
import { renderReview } from "./views/review.js";
import { renderRules } from "./views/rules.js";
import { renderAdmin } from "./views/admin.js";

const NAV = [
  { hash: "#/dashboard", label: "Dashboard", icon: "dashboard", title: "Workspace overview",
    eyebrow: "Home", subtitle: "Hunting activity, observations and detection coverage" },
  { hash: "#/hypotheses", label: "Hypotheses", icon: "target", title: "Hypothesis catalogue",
    eyebrow: "Library", subtitle: "Threat intelligence scenarios, techniques and mathematical models" },
  { hash: "#/hunt/new", label: "New hunt", icon: "play", title: "Run a hunt",
    eyebrow: "Execute", subtitle: "Select a hypothesis, upload the evidence and analyse" },
  { hash: "#/hunts", label: "Hunts", icon: "list", title: "Hunts",
    eyebrow: "History", subtitle: "Every analysis executed in this workspace" },
  { hash: "#/rules", label: "Detection library", icon: "shield", title: "Detection library",
    eyebrow: "Engine", subtitle: "The rules and statistical models behind every hunt" },
  { hash: "#/review", label: "Review queue", icon: "target", title: "Hypothesis review queue",
    eyebrow: "Threat intel", subtitle: "Hypotheses derived from public reporting, waiting to be accepted" },
  { hash: "#/admin", label: "Workspace", icon: "users", title: "Workspace settings",
    eyebrow: "Administration", subtitle: "Members, roles and activity log" },
];

const root = document.getElementById("app");
let cleanup = null;
// Asked for once per session rather than on every route change. The server caches
// it too, so a missing model server costs one refused connection, not one per page.
let aiStatus = null;

function aiChip() {
  const dot = el("span", { class: "ai-dot" });
  const label = el("span", { text: "AI" });
  const chip = el("span", { class: "tag ai-chip", title: "Checking the local model layer" }, [dot, label]);

  function apply(status) {
    if (!status || !status.enabled) {
      chip.remove();
      return;
    }
    const model = status.model || {};
    const ready = Boolean(status.ready);
    chip.className = `tag ai-chip ${ready ? "tag-green" : ""}`;
    dot.dataset.state = ready ? "ready" : status.reachable ? "degraded" : "offline";
    label.textContent = ready ? model.tag || "AI ready" : status.reachable ? "AI degraded" : "AI offline";
    if (ready) {
      chip.title = `Local model ${model.tag} running on ${(status.hardware || {}).accelerator || "this host"}`;
    } else {
      const reason = status.degraded_reason || "The local model layer is unavailable";
      chip.title = model.pull_command ? `${reason}. Run: ${model.pull_command}` : reason;
    }
  }

  if (aiStatus) apply(aiStatus);
  else {
    api.aiStatus()
      .then((status) => {
        aiStatus = status;
        apply(status);
      })
      .catch(() => chip.remove());
  }
  return chip;
}

function navigate(hash) {
  if (window.location.hash === hash) render();
  else window.location.hash = hash;
}

function parseRoute() {
  const raw = (window.location.hash || "#/dashboard").slice(1);
  const [path, query = ""] = raw.split("?");
  const segments = path.split("/").filter(Boolean);
  return { segments, params: new URLSearchParams(query), path: `#/${segments.join("/")}` };
}

function shell(route) {
  const session = auth.session || {};
  const user = session.user || {};
  const tenant = session.tenant || {};
  const active = NAV.find((item) => route.path.startsWith(item.hash)) ||
    (route.segments[0] === "report" ? { title: "Hunt report", eyebrow: "Report",
      subtitle: "Observations, evidence and recommendations", hash: "#/hunts" } : NAV[0]);

  const sidebar = el("aside", { class: "sidebar", id: "sidebar" }, [
    el("div", { class: "brand" }, [
      el("div", { class: "brand-mark", html: 'Threat Hunting<br>Factory<span class="dot">.</span>' }),
      el("div", { class: "brand-sub", text: "Detection and response" }),
    ]),
    el("nav", { class: "nav" }, [
      el("div", { class: "nav-group-label", text: "Hunting" }),
      ...NAV.slice(0, 4).map(navItem),
      el("div", { class: "nav-group-label", text: "Platform" }),
      ...NAV.slice(4).map(navItem),
    ]),
    el("div", { class: "sidebar-footer" }, [
      el("div", { class: "user-chip" }, [
        el("div", { class: "avatar", text: initials(user.full_name || user.email || "?") }),
        el("div", { style: "min-width:0" }, [
          el("strong", { class: "truncate", text: user.full_name || user.email || "" }),
          el("span", { text: `${tenant.name || ""} | ${user.role || ""}` }),
        ]),
      ]),
      el("button", {
        class: "btn btn-ghost btn-sm btn-block",
        style: "border-color:#3a3a3a;color:#cfcfcd",
        onclick: () => {
          auth.clear();
          toast("Signed out");
          render();
        },
      }, "Sign out"),
    ]),
  ]);

  function navItem(item) {
    return el("a", {
      class: `nav-item ${route.path.startsWith(item.hash) ? "active" : ""}`,
      href: item.hash,
      onclick: () => document.getElementById("sidebar")?.classList.remove("open"),
    }, [icon(item.icon), el("span", { text: item.label })]);
  }

  const content = el("div", { class: "content" });
  const main = el("main", { class: "main" }, [
    el("header", { class: "topbar" }, [
      el("div", {}, [
        el("div", { class: "eyebrow", text: active.eyebrow }),
        el("h1", { text: active.title }),
        el("div", { class: "muted text-sm mt-1", text: active.subtitle }),
      ]),
      el("div", { class: "row" }, [
        aiChip(),
        el("button", {
          class: "btn btn-ghost btn-sm menu-toggle",
          onclick: () => document.getElementById("sidebar")?.classList.toggle("open"),
        }, "Menu"),
        el("button", { class: "btn", onclick: () => navigate("#/hunt/new") }, "New hunt"),
      ]),
    ]),
    content,
  ]);

  clear(root).appendChild(el("div", { class: "app-shell" }, [sidebar, main]));
  return content;
}

function initials(value) {
  return value.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((part) => part[0].toUpperCase()).join("");
}

async function render() {
  if (cleanup) {
    cleanup();
    cleanup = null;
  }
  if (!auth.isAuthenticated) {
    renderAuth(root, () => navigate("#/dashboard"));
    return;
  }
  const route = parseRoute();
  const content = shell(route);
  const [head, second] = route.segments;
  try {
    if (head === "hypotheses") await renderHypotheses(content, navigate);
    else if (head === "hunt" && second === "new") cleanup = await renderNewHunt(content, navigate, route.params);
    else if (head === "hunts") await renderHunts(content, navigate);
    else if (head === "report" && second) await renderReport(content, navigate, second);
    else if (head === "rules") await renderRules(content);
    else if (head === "review") await renderReview(content);
    else if (head === "admin") await renderAdmin(content);
    else await renderDashboard(content, navigate);
  } catch (error) {
    if (error && error.status === 401) return;
    console.error(error);
    toast(error.message || "Something went wrong", "error");
  }
}

window.addEventListener("hashchange", render);
window.addEventListener("thf:unauthorised", () => {
  toast("Your session has expired", "error");
  render();
});

// Refresh the stored session on start up so role changes are picked up.
(async () => {
  if (auth.isAuthenticated) {
    try {
      const session = await api.me();
      auth.update(session);
    } catch (error) {
      /* the request helper already handled an expired token */
    }
  }
  render();
})();
