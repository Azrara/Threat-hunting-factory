import { api } from "../api.js";
import { barList, clear, el, emptyState, formatNumber, spinner } from "../ui.js";

export async function renderRules(root) {
  clear(root).appendChild(spinner("Loading the detection library"));
  let payload;
  try {
    payload = await api.rules();
  } catch (error) {
    clear(root).appendChild(emptyState("Library unavailable", error.message));
    return;
  }

  const stats = payload.statistics;
  let search = "";
  let type = "all";
  const body = el("tbody");

  clear(root);
  root.appendChild(el("div", { class: "grid grid-4 mb-3" }, [
    kpi("Detections", formatNumber(stats.total), "Rules in the library"),
    kpi("ATT&CK techniques", formatNumber(stats.mitre_techniques), "Distinct techniques covered"),
    kpi("Detection styles", formatNumber(Object.keys(stats.by_type).length), "Pattern, threshold, sequence, statistical"),
    kpi("Categories", formatNumber(Object.keys(stats.by_category).length), "Across the attack lifecycle"),
  ]));

  root.appendChild(el("div", { class: "grid grid-2 mb-3" }, [
    panel("Detections by style", barList(Object.entries(stats.by_type).map(([name, value]) =>
      ({ name: name.replace(/_/g, " "), value })))),
    panel("Detections by category", barList(Object.entries(stats.by_category)
      .sort((a, b) => b[1] - a[1]).slice(0, 10)
      .map(([name, value]) => ({ name: name.replace(/_/g, " "), value, colour: "#53565a" })))),
  ]));

  const filters = el("div", { class: "filters" }, [
    ...["all", "pattern", "threshold", "sequence", "statistical"].map((key) =>
      el("button", {
        class: `chip ${key === "all" ? "active" : ""}`, dataset: { type: key },
        text: key === "all" ? "All styles" : key,
        onclick: (event) => {
          type = key;
          filters.querySelectorAll("[data-type]").forEach((chip) =>
            chip.classList.toggle("active", chip.dataset.type === key));
          fill();
        },
      })),
    el("div", { class: "spacer" }),
    el("input", {
      class: "input", type: "search", placeholder: "Search rules, techniques or categories",
      style: "max-width:320px",
      oninput: (event) => { search = event.target.value.trim().toLowerCase(); fill(); },
    }),
  ]);

  root.appendChild(el("section", { class: "card" }, [
    el("div", { class: "card-head" }, [
      el("div", {}, [
        el("h2", { text: "Detection library" }),
        el("div", { class: "muted text-sm mt-1",
          text: "Every rule the engine can apply, with its severity, style and ATT&CK mapping." }),
      ]),
    ]),
    el("div", { class: "card-body", style: "padding-top:12px" }, [
      filters,
      el("div", { class: "table-wrap" }, [
        el("table", { class: "data" }, [
          el("thead", {}, el("tr", {},
            ["Detection", "Style", "Severity", "Category", "ATT&CK", "Telemetry"].map((h) => el("th", { text: h })))),
          body,
        ]),
      ]),
    ]),
  ]));
  fill();

  function fill() {
    clear(body);
    const rows = payload.items.filter((rule) => {
      if (type !== "all" && rule.detection_type !== type) return false;
      if (!search) return true;
      return [rule.id, rule.name, rule.category, rule.mitre_technique, rule.mitre_technique_id, rule.mitre_tactic]
        .join(" ").toLowerCase().includes(search);
    });
    if (!rows.length) {
      body.appendChild(el("tr", {}, el("td", { colspan: "6" },
        emptyState("No detection matches", "Adjust the filters or the search."))));
      return;
    }
    for (const rule of rows) {
      body.appendChild(el("tr", {}, [
        el("td", {}, [
          el("div", { style: "font-weight:600;font-size:13px", text: rule.name.replace(/\{[^}]+\}/g, "").trim() }),
          el("div", { class: "mono muted", style: "font-size:11px", text: rule.id }),
        ]),
        el("td", { class: "text-sm", text: rule.detection_type }),
        el("td", {}, el("span", { class: `sev sev-${rule.severity}`, text: rule.severity })),
        el("td", { class: "text-sm muted", text: (rule.category || "").replace(/_/g, " ") }),
        el("td", { class: "text-sm" }, [
          el("div", { text: rule.mitre_technique_id || "" }),
          el("div", { class: "muted", style: "font-size:11.5px", text: rule.mitre_tactic || "" }),
        ]),
        el("td", { class: "text-sm muted truncate", style: "max-width:200px",
          text: (rule.data_sources || []).join(", ").replace(/_/g, " ") || "any" }),
      ]));
    }
  }

  function kpi(label, value, hint) {
    return el("div", { class: "card kpi" }, [
      el("div", { class: "label", text: label }),
      el("div", { class: "value", text: value }),
      el("div", { class: "hint", text: hint }),
    ]);
  }

  function panel(title, content) {
    return el("section", { class: "card" }, [
      el("div", { class: "card-head" }, [el("h3", { text: title })]),
      el("div", { class: "card-body" }, [content]),
    ]);
  }
}
