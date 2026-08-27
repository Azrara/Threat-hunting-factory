import { api } from "../api.js";
import {
  SEVERITIES, SEVERITY_COLOURS, barList, clear, donut, el, emptyState, formatBytes,
  formatDate, formatNumber, legend, riskClass, severityBadge, spinner, toast,
} from "../ui.js";

export async function renderReport(root, navigate, huntId) {
  clear(root).appendChild(spinner("Loading the report"));
  let payload;
  let hunt;
  try {
    hunt = await api.hunt(huntId);
    if (hunt.status !== "completed") {
      clear(root).appendChild(emptyState(
        hunt.status === "failed" ? "This hunt failed" : "This hunt is still running",
        hunt.status === "failed" ? (hunt.error || "The engine could not complete the analysis")
                                 : `${hunt.stage} (${hunt.progress}%)`,
        el("button", { class: "btn mt-2", onclick: () => navigate("#/hunts") }, "Back to hunts")));
      return;
    }
    payload = await api.observations(huntId);
  } catch (error) {
    clear(root).appendChild(emptyState("Report unavailable", error.message));
    return;
  }

  const observations = payload.items;
  const summary = hunt.summary || {};
  const coverage = hunt.coverage || {};
  const filters = { severity: "all", category: "all", search: "" };

  clear(root);
  root.appendChild(hero());
  root.appendChild(metricRow());
  root.appendChild(analyticsRow());
  if ((coverage.required || []).length || (summary.warnings || []).length) root.appendChild(coveragePanel());

  const list = el("div");
  root.appendChild(el("section", { class: "card mt-3" }, [
    el("div", { class: "card-head" }, [
      el("div", {}, [
        el("h2", { text: `Observations (${observations.length})` }),
        el("div", { class: "muted text-sm mt-1",
          text: "Each observation carries the original evidence, the cyber risk, the impact and the recommendation." }),
      ]),
      el("div", { class: "row" }, [
        el("button", { class: "btn btn-ghost btn-sm", onclick: () => toggleAll(true) }, "Expand all"),
        el("button", { class: "btn btn-ghost btn-sm", onclick: () => toggleAll(false) }, "Collapse all"),
      ]),
    ]),
    el("div", { class: "card-body" }, [filterBar(), list]),
  ]));
  fill();

  // ---------------------------------------------------------------- pieces

  function hero() {
    return el("section", { class: "report-hero mb-3" }, [
      el("div", { class: `risk-badge ${riskClass(hunt.risk_score)}` }, [
        el("div", { class: "n", text: hunt.risk_score.toFixed(0) }),
        el("div", { class: "l", text: "risk score" }),
      ]),
      el("div", { style: "flex:1;min-width:260px" }, [
        el("div", { style: "font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#86bc25;margin-bottom:8px",
          text: hunt.verdict }),
        el("h1", { text: hunt.title || hunt.hypothesis_name }),
        el("div", { class: "sub", text: hunt.hypothesis_name }),
        el("div", { class: "sub mt-2", text:
          `${hunt.archive_name} | ${formatBytes(hunt.archive_bytes)} | completed ${formatDate(hunt.completed_at)}` }),
      ]),
      el("div", { class: "row wrap" }, [
        el("button", { class: "btn", onclick: async (event) => {
          const button = event.currentTarget;
          button.disabled = true;
          button.textContent = "Preparing ...";
          try {
            await api.download(`/api/hunts/${hunt.id}/report.pdf`, "threat-hunting-report.pdf");
            toast("PDF report downloaded");
          } catch (error) {
            toast(error.message, "error");
          } finally {
            button.disabled = false;
            button.textContent = "Export PDF";
          }
        } }, "Export PDF"),
        el("button", { class: "btn btn-ghost", style: "border-color:#4a4a4a;color:#fff", onclick: async () => {
          try {
            await api.download(`/api/hunts/${hunt.id}/report.json`, "threat-hunting-report.json");
            toast("JSON export downloaded");
          } catch (error) {
            toast(error.message, "error");
          }
        } }, "Export JSON"),
        el("button", { class: "btn btn-ghost", style: "border-color:#4a4a4a;color:#fff", onclick: async () => {
          try {
            await api.rerun(hunt.id);
            toast("The hunt has been queued again");
            navigate("#/hunts");
          } catch (error) {
            toast(error.message, "error");
          }
        } }, "Run again"),
      ]),
    ]);
  }

  function metricRow() {
    const cells = [
      ["Records parsed", formatNumber(hunt.events_parsed)],
      ["Log files", formatNumber(hunt.files_analysed)],
      ["Detections applied", formatNumber(hunt.rules_evaluated)],
      ["Observations", formatNumber(hunt.observation_count)],
      ["Analysis time", `${(hunt.duration_ms / 1000).toFixed(1)} s`],
    ];
    return el("div", { class: "grid mb-3", style: "grid-template-columns:repeat(5,minmax(0,1fr))" },
      cells.map(([label, value]) =>
        el("div", { class: "card kpi" }, [
          el("div", { class: "label", text: label }),
          el("div", { class: "value", style: "font-size:24px", text: value }),
        ])
      ));
  }

  function analyticsRow() {
    const severityCounts = {};
    for (const severity of SEVERITIES) {
      severityCounts[severity] = observations.filter((item) => item.severity === severity).length;
    }
    const techniques = (summary.top_techniques || []).map((entry) => ({
      name: Array.isArray(entry) ? entry[0] : String(entry),
      value: Array.isArray(entry) ? entry[1] : 0,
      colour: "#0f0f0f",
    }));
    const categories = Object.entries(summary.categories || {})
      .map(([name, value]) => ({ name: name.replace(/_/g, " "), value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);

    return el("div", { class: "grid grid-3 mb-3" }, [
      panel("Severity breakdown", el("div", {}, [
        el("div", { style: "display:flex;justify-content:center;margin-bottom:16px" }, [
          donut(SEVERITIES.map((name) => ({ name, value: severityCounts[name], colour: SEVERITY_COLOURS[name] })),
            { centreLabel: "observations", centreValue: observations.length }),
        ]),
        legend(SEVERITIES.map((name) => ({ name, value: severityCounts[name], colour: SEVERITY_COLOURS[name] }))),
      ])),
      panel("Techniques observed", techniques.length
        ? barList(techniques.slice(0, 8))
        : el("p", { class: "muted text-sm", text: "No technique mapped for this hunt." })),
      panel("Detection categories", categories.length
        ? barList(categories)
        : el("p", { class: "muted text-sm", text: "No categories recorded." })),
    ]);
  }

  function coveragePanel() {
    const required = coverage.required || [];
    const optional = coverage.optional || [];
    const files = summary.files || [];
    return el("section", { class: "card mb-3" }, [
      el("div", { class: "card-head" }, [
        el("div", {}, [
          el("h2", { text: "Evidence and data source coverage" }),
          el("div", { class: "muted text-sm mt-1",
            text: "Missing telemetry limits what the hypothesis can confirm or reject." }),
        ]),
      ]),
      el("div", { class: "card-body grid grid-2" }, [
        el("div", {}, [
          el("div", { class: "section-label", text: "Data sources" }),
          ...(required.length ? required.map((entry) => sourceRow(entry, true)) : [
            el("p", { class: "muted text-sm", text: "This hypothesis has no mandatory data source." }),
          ]),
          ...optional.filter((entry) => entry.present).map((entry) => sourceRow(entry, false)),
          (summary.warnings || []).length
            ? el("div", {}, [
                el("div", { class: "section-label", text: "Processing notes" }),
                ...summary.warnings.map((note) => el("p", { class: "text-sm muted", text: `- ${note}` })),
              ])
            : null,
        ]),
        el("div", {}, [
          el("div", { class: "section-label", text: `Files analysed (${files.length})` }),
          el("div", { class: "table-wrap" }, [
            el("table", { class: "data" }, [
              el("thead", {}, el("tr", {}, ["File", "Format", "Telemetry", "Records"].map((h) => el("th", { text: h })))),
              el("tbody", {}, files.map((file) =>
                el("tr", {}, [
                  el("td", { class: "mono", style: "font-size:11.5px", text: file.path }),
                  el("td", { class: "text-sm", text: file.log_format }),
                  el("td", { class: "text-sm muted", text: (file.data_source || "").replace(/_/g, " ") }),
                  el("td", { class: "text-sm", text: formatNumber(file.events) }),
                ])
              )),
            ]),
          ]),
        ]),
      ]),
    ]);
  }

  function sourceRow(entry, required) {
    return el("div", { class: "row-between", style: "padding:10px 0;border-bottom:1px solid var(--line-soft)" }, [
      el("div", {}, [
        el("div", { style: "font-size:13.5px;font-weight:600", text: entry.name }),
        el("div", { class: "muted text-sm", text: `${formatNumber(entry.events)} records` }),
      ]),
      el("span", {
        class: `tag ${entry.present ? "tag-green" : ""}`,
        style: entry.present ? "" : "color:var(--critical);border-color:#f3c2c5;background:#fdeced",
        text: entry.present ? "present" : (required ? "missing" : "not supplied"),
      }),
    ]);
  }

  function panel(title, body) {
    return el("section", { class: "card" }, [
      el("div", { class: "card-head" }, [el("h3", { text: title })]),
      el("div", { class: "card-body" }, [body]),
    ]);
  }

  function filterBar() {
    const categories = [...new Set(observations.map((item) => item.category).filter(Boolean))].sort();
    return el("div", { class: "filters" }, [
      ...["all", ...SEVERITIES].map((key) =>
        el("button", {
          class: `chip ${key === "all" ? "active" : ""}`, dataset: { severity: key },
          text: key === "all"
            ? `All (${observations.length})`
            : `${key} (${observations.filter((item) => item.severity === key).length})`,
          onclick: (event) => {
            filters.severity = key;
            event.target.parentElement.querySelectorAll("[data-severity]").forEach((chip) =>
              chip.classList.toggle("active", chip.dataset.severity === key));
            fill();
          },
        })
      ),
      el("select", {
        class: "input", style: "max-width:210px",
        onchange: (event) => { filters.category = event.target.value; fill(); },
      }, [
        el("option", { value: "all", text: "All categories" }),
        ...categories.map((category) =>
          el("option", { value: category, text: category.replace(/_/g, " ") })),
      ]),
      el("input", {
        class: "input", type: "search", placeholder: "Search observations, hosts, rules",
        style: "max-width:280px",
        oninput: (event) => { filters.search = event.target.value.trim().toLowerCase(); fill(); },
      }),
    ]);
  }

  function fill() {
    clear(list);
    const rows = observations.filter((item) => {
      if (filters.severity !== "all" && item.severity !== filters.severity) return false;
      if (filters.category !== "all" && item.category !== filters.category) return false;
      if (!filters.search) return true;
      const haystack = [item.title, item.description, item.entity, item.rule_id, item.mitre_technique]
        .join(" ").toLowerCase();
      return haystack.includes(filters.search);
    });
    if (!rows.length) {
      list.appendChild(emptyState(
        observations.length ? "Nothing matches the filters" : "No observation was raised",
        observations.length
          ? "Adjust the severity, category or search filters."
          : "The hypothesis was not confirmed by this evidence. Check the data source coverage above before concluding."
      ));
      return;
    }
    rows.forEach((item, index) => list.appendChild(observationCard(item, index + 1)));
  }

  function toggleAll(open) {
    list.querySelectorAll(".obs").forEach((node) => {
      node.classList.toggle("open", open);
      const body = node.querySelector(".obs-body");
      if (body) body.classList.toggle("hidden", !open);
    });
  }

  function observationCard(item, index) {
    const body = el("div", { class: "obs-body hidden" }, [
      el("div", { class: "kv-grid mt-2" }, [
        kv("Detection", item.rule_id),
        kv("Type", item.detection_type),
        kv("Confidence", item.confidence),
        kv("Affected entity", item.entity || "not attributed"),
        kv("Telemetry", (item.data_source || "").replace(/_/g, " ")),
        kv("Occurrences", formatNumber(item.event_count)),
        kv("First seen", item.first_seen ? formatDate(item.first_seen) : "not available"),
        kv("Last seen", item.last_seen ? formatDate(item.last_seen) : "not available"),
      ]),
      el("div", { class: "obs-section-title", text: "What was detected" }),
      el("p", { text: item.description }),
      ...(item.evidence || []).length ? [el("div", { class: "obs-section-title", text: "Original log evidence" })] : [],
      ...(item.evidence || []).slice(0, 6).map((evidence) =>
        el("div", {}, [
          el("div", { class: "evidence-meta" }, [
            el("span", { text: evidence.source_file || "" }),
            el("span", { text: `line ${evidence.line_no}` }),
            el("span", { text: evidence.timestamp || "no timestamp" }),
            el("span", { text: evidence.log_format || "" }),
          ]),
          el("pre", { class: "evidence", text: evidence.excerpt || "" }),
        ])
      ),
      Object.keys(item.metrics || {}).length
        ? el("div", {}, [
            el("div", { class: "obs-section-title", text: "Analytical detail" }),
            el("div", { class: "kv-grid" }, Object.entries(item.metrics).slice(0, 14).map(([key, value]) =>
              kv(key.replace(/_/g, " "), Array.isArray(value) ? value.slice(0, 8).join(", ") : String(value)))),
          ])
        : null,
      item.risk ? callout("Cyber risk", item.risk, "callout-risk") : null,
      item.impact ? callout("Cyber impact", item.impact, "callout-impact") : null,
      item.recommendation ? callout("Recommendation", item.recommendation, "callout-reco") : null,
      (item.references || []).length
        ? el("div", { class: "text-sm muted mt-2" }, [
            "References: ",
            ...item.references.map((reference) =>
              el("a", { href: reference, target: "_blank", rel: "noopener",
                style: "color:var(--green-dark);margin-right:10px", text: reference })),
          ])
        : null,
    ]);

    const card = el("article", { class: "obs" }, [
      el("div", {
        class: "obs-head",
        onclick: () => {
          card.classList.toggle("open");
          body.classList.toggle("hidden");
        },
      }, [
        el("span", { class: "idx", text: `OBS-${String(index).padStart(3, "0")}` }),
        el("div", { class: "title" }, [
          el("h3", { text: item.title }),
          el("div", { class: "meta" }, [
            el("span", { text: item.mitre_technique_id ? `${item.mitre_technique_id} ${item.mitre_technique}` : item.category }),
            item.entity ? el("span", { text: `Entity: ${item.entity}` }) : null,
            el("span", { text: `${formatNumber(item.event_count)} event${item.event_count > 1 ? "s" : ""}` }),
          ]),
        ]),
        severityBadge(item.severity),
        el("span", { class: "caret", text: "›" }),
      ]),
      body,
    ]);
    return card;
  }

  function kv(key, value) {
    return el("div", { class: "kv" }, [
      el("div", { class: "k", text: key }),
      el("div", { class: "v", text: value === "" || value === null || value === undefined ? "-" : String(value) }),
    ]);
  }

  function callout(title, text, variant) {
    return el("div", { class: `callout ${variant} mt-2` }, [
      el("h4", { text: title }),
      el("p", { text }),
    ]);
  }
}
