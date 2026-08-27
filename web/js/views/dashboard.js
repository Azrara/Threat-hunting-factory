import { api } from "../api.js";
import {
  SEVERITIES, SEVERITY_COLOURS, FAMILY_LABELS, barList, clear, donut, el, emptyState,
  formatNumber, legend, relativeTime, riskClass, spinner, statusBadge, timelineChart, toast,
} from "../ui.js";

export async function renderDashboard(root, navigate) {
  clear(root).appendChild(spinner("Loading workspace statistics"));
  let data;
  try {
    data = await api.stats(90);
  } catch (error) {
    clear(root).appendChild(emptyState("Statistics unavailable", error.message));
    return;
  }

  const totals = data.totals;
  clear(root);

  root.appendChild(el("div", { class: "grid grid-4 mb-3" }, [
    kpi("Hunts executed", formatNumber(totals.hunts), `${formatNumber(totals.hunts_in_period)} in the last 90 days`),
    kpi("Observations", formatNumber(totals.observations),
      `${formatNumber((data.severity.critical || 0) + (data.severity.high || 0))} high or critical`,
      (data.severity.critical || 0) > 0 ? "accent-critical" : ""),
    kpi("Records analysed", formatNumber(totals.events_analysed),
      `${formatNumber(totals.files_analysed)} log files parsed`, "accent-black"),
    kpi("Average risk score", `${totals.average_risk_score}`,
      `Peak ${totals.highest_risk_score} out of 100`,
      totals.average_risk_score >= 50 ? "accent-high" : "accent-medium"),
  ]));

  const severityData = SEVERITIES
    .map((name) => ({ name, value: data.severity[name] || 0, colour: SEVERITY_COLOURS[name] }))
    .filter((item) => item.value > 0);

  root.appendChild(el("div", { class: "grid grid-sidebar mb-3" }, [
    card("Hunting activity", "Hunts and observations recorded per day",
      data.timeline.length
        ? el("div", {}, [
            timelineChart(data.timeline.map((point) => ({
              label: point.date,
              shortLabel: point.date.slice(5),
              value: point.observations,
            })), { height: 170 }),
            el("div", { class: "row mt-2 text-sm muted" }, [
              el("span", { text: `${formatNumber(data.timeline.reduce((sum, p) => sum + p.hunts, 0))} hunts` }),
              el("span", { text: "|" }),
              el("span", { text: `${formatNumber(data.timeline.reduce((sum, p) => sum + p.observations, 0))} observations` }),
              el("span", { text: "|" }),
              el("span", { text: `${formatNumber(data.timeline.reduce((sum, p) => sum + p.critical, 0))} critical` }),
            ]),
          ])
        : emptyState("No activity yet", "Run your first hunt to populate the timeline.")),
    card("Observation severity", "Across every completed hunt",
      el("div", {}, [
        el("div", { style: "display:flex;justify-content:center;margin-bottom:18px" }, [
          donut(severityData, { centreLabel: "observations", centreValue: formatNumber(totals.observations) }),
        ]),
        legend(SEVERITIES.map((name) => ({
          name, value: data.severity[name] || 0, colour: SEVERITY_COLOURS[name],
        }))),
      ])),
  ]));

  root.appendChild(el("div", { class: "grid grid-2 mb-3" }, [
    card("MITRE ATT&CK tactics", "Where the observations sit in the attack lifecycle",
      data.tactics.length
        ? barList(data.tactics.slice(0, 8).map((item) => ({ name: item.name, value: item.count })))
        : emptyState("No mapped tactics yet", "Observations are mapped to ATT&CK automatically.")),
    card("Most frequent techniques", "Top detections by observation count",
      data.techniques.length
        ? barList(data.techniques.slice(0, 8).map((item) => ({
            name: `${item.id} ${item.name}`, value: item.count, colour: "#0f0f0f",
          })))
        : emptyState("No techniques yet", "Run a hunt to build technique coverage.")),
  ]));

  root.appendChild(el("div", { class: "grid grid-3 mb-3" }, [
    card("Hypotheses explored", `${totals.hypotheses_used} of ${totals.hypotheses_available} used`,
      data.top_hypotheses.length
        ? el("div", {}, data.top_hypotheses.map((item) =>
            el("div", { class: "row-between", style: "padding:9px 0;border-bottom:1px solid var(--line-soft)" }, [
              el("div", { style: "min-width:0" }, [
                el("div", { class: "truncate", style: "font-size:13px;font-weight:600", title: item.name, text: item.name }),
                el("div", { class: "muted text-sm", text: FAMILY_LABELS[item.family] || item.family }),
              ]),
              el("span", { class: "tag tag-dark", text: String(item.count) }),
            ])
          ))
        : emptyState("Nothing yet", "Pick a hypothesis to get started.")),
    card("Telemetry analysed", "Records normalised per data source",
      data.data_sources.length
        ? barList(data.data_sources.slice(0, 8).map((item) => ({
            name: item.name.replace(/_/g, " "), value: item.events, colour: "#53565a",
          })))
        : emptyState("No telemetry yet", "Upload an evidence archive to see the breakdown.")),
    card("Detection engine", `${data.engine.total} detections, ${data.engine.mitre_techniques} techniques`,
      barList(Object.entries(data.engine.by_type).map(([name, value]) => ({
        name: name.replace(/_/g, " "), value, colour: "#86bc25",
      })))),
  ]));

  const recent = data.recent_hunts;
  root.appendChild(card("Recent hunts", "Latest analyses in this workspace",
    recent.length
      ? el("div", { class: "table-wrap" }, [
          el("table", { class: "data" }, [
            el("thead", {}, el("tr", {}, ["Hunt", "Hypothesis", "Status", "Observations", "Risk", "Created"]
              .map((label) => el("th", { text: label })))),
            el("tbody", {}, recent.map((hunt) =>
              el("tr", {
                class: "clickable",
                onclick: () => navigate(hunt.status === "completed" ? `#/report/${hunt.id}` : "#/hunts"),
              }, [
                el("td", {}, el("strong", { text: hunt.title || hunt.hypothesis_name })),
                el("td", { class: "muted text-sm truncate", style: "max-width:260px", text: hunt.hypothesis_name }),
                el("td", {}, statusBadge(hunt.status)),
                el("td", { text: formatNumber(hunt.observation_count) }),
                el("td", {}, el("span", {
                  class: `tag ${riskClass(hunt.risk_score) ? "tag-dark" : "tag-green"}`,
                  text: `${hunt.risk_score.toFixed(0)}/100`,
                })),
                el("td", { class: "muted text-sm nowrap", text: relativeTime(hunt.created_at) }),
              ])
            )),
          ]),
        ])
      : emptyState("No hunts yet", "Choose a hypothesis and upload evidence to run your first hunt.",
          el("button", { class: "btn mt-2", onclick: () => navigate("#/hypotheses") }, "Browse hypotheses"))
  ));

  function kpi(label, value, hint, accent = "") {
    return el("div", { class: `card kpi ${accent}` }, [
      el("div", { class: "label", text: label }),
      el("div", { class: "value", text: value }),
      el("div", { class: "hint", text: hint }),
    ]);
  }

  function card(title, subtitle, body) {
    return el("section", { class: "card" }, [
      el("div", { class: "card-head" }, [
        el("div", {}, [
          el("h3", { text: title }),
          subtitle ? el("div", { class: "muted text-sm mt-1", text: subtitle }) : null,
        ]),
      ]),
      el("div", { class: "card-body" }, [body]),
    ]);
  }
}
