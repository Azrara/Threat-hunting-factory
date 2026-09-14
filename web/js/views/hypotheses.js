import { api } from "../api.js";
import { FAMILY_LABELS, clear, el, emptyState, spinner, toast } from "../ui.js";

const FAMILY_TAGS = {
  cti: "Threat intelligence scenario",
  technique: "Technique based hunt",
  mathematical: "Mathematical model",
};

export async function renderHypotheses(root, navigate) {
  clear(root).appendChild(spinner("Loading the hypothesis catalogue"));
  let payload;
  try {
    payload = await api.hypotheses();
  } catch (error) {
    clear(root).appendChild(emptyState("Catalogue unavailable", error.message));
    return;
  }

  let family = "all";
  let origin = "all";
  let search = "";
  const grid = el("div", { class: "hyp-grid" });

  const filters = el("div", { class: "filters" }, [
    ...["all", "cti", "technique", "mathematical"].map((key) =>
      el("button", {
        class: `chip ${key === family ? "active" : ""}`,
        dataset: { family: key },
        text: key === "all" ? "All hypotheses" : FAMILY_LABELS[key],
        onclick: (event) => {
          family = key;
          filters.querySelectorAll(".chip").forEach((chip) =>
            chip.classList.toggle("active", chip.dataset.family === key));
          draw();
        },
      })
    ),
    el("div", { class: "spacer" }),
    el("select", {
      class: "input", style: "max-width:190px",
      onchange: (event) => {
        origin = event.target.value;
        draw();
      },
    }, [
      el("option", { value: "all", text: "Every origin" }),
      el("option", { value: "builtin", text: "Built in" }),
      el("option", { value: "generated", text: "From reporting" }),
    ]),
    el("input", {
      class: "input", type: "search", placeholder: "Search actors, tactics or keywords",
      style: "max-width:300px",
      oninput: (event) => {
        search = event.target.value.trim().toLowerCase();
        draw();
      },
    }),
  ]);

  clear(root);
  root.appendChild(filters);
  root.appendChild(grid);

  function matches(item) {
    if (family !== "all" && item.family !== family) return false;
    if (origin !== "all" && (item.origin || "builtin") !== origin) return false;
    if (!search) return true;
    const haystack = [
      item.name, item.summary, item.narrative, item.rationale,
      ...(item.threat_actors || []), ...(item.mitre_tactics || []), ...(item.techniques || []),
    ].join(" ").toLowerCase();
    return haystack.includes(search);
  }

  function draw() {
    const items = payload.items.filter(matches);
    clear(grid);
    if (!items.length) {
      grid.appendChild(emptyState("No hypothesis matches", "Adjust the filters or clear the search."));
      return;
    }
    for (const item of items) grid.appendChild(cardFor(item));
  }

  function cardFor(item) {
    return el("article", { class: `hyp-card family-${item.family}`, onclick: () => openDrawer(item.id) }, [
      el("div", { class: "row-between" }, [
        el("span", { class: "tag", text: FAMILY_TAGS[item.family] || item.family }),
        el("span", { class: `tag ${item.priority === "critical" ? "tag-dark" : ""}`, text: item.priority }),
      ]),
      item.origin === "generated"
        ? el("span", { class: "tag tag-green mb-1", text: "From reporting" })
        : null,
      el("h3", { text: item.name }),
      el("p", { text: item.summary }),
      el("div", { class: "hyp-meta" }, [
        el("span", {
          class: `tag ${item.rule_count ? "tag-green" : ""}`,
          text: item.rule_count ? `${item.rule_count} detections` : "No detection yet",
        }),
        el("span", { class: "tag", text: `${item.techniques.length} techniques` }),
        ...(item.required_data_sources.length
          ? [el("span", { class: "tag", text: `${item.required_data_sources.length} required source${item.required_data_sources.length > 1 ? "s" : ""}` })]
          : [el("span", { class: "tag", text: "Any telemetry" })]),
      ]),
    ]);
  }

  async function openDrawer(id) {
    const backdrop = el("div", { class: "drawer-backdrop", onclick: (event) => {
      if (event.target === backdrop) backdrop.remove();
    } });
    const drawer = el("div", { class: "drawer" }, [spinner("Loading hypothesis")]);
    backdrop.appendChild(drawer);
    document.body.appendChild(backdrop);
    let detail;
    try {
      detail = await api.hypothesis(id);
    } catch (error) {
      toast(error.message, "error");
      backdrop.remove();
      return;
    }
    clear(drawer);
    drawer.appendChild(el("div", { class: "drawer-head" }, [
      el("button", { class: "drawer-close", text: "×", onclick: () => backdrop.remove() }),
      el("div", { class: "row wrap mb-2" }, [
        el("span", { class: "tag tag-green", text: FAMILY_TAGS[detail.family] }),
        el("span", { class: "tag tag-dark", text: `Priority ${detail.priority}` }),
      ]),
      el("h2", { text: detail.name }),
      el("div", { style: "color:#adadab;font-size:13.5px;line-height:1.6", text: detail.summary }),
    ]));

    const body = el("div", { class: "drawer-body" });
    body.appendChild(el("div", { class: "section-label", text: "Hunting narrative" }));
    body.appendChild(el("p", { text: detail.narrative }));
    body.appendChild(el("div", { class: "section-label", text: "What we expect to see if it is true" }));
    body.appendChild(el("p", { text: detail.rationale }));
    body.appendChild(el("div", { class: "section-label", text: "Analytical method" }));
    body.appendChild(el("p", { text: detail.method }));

    if (detail.source) {
      body.appendChild(el("div", { class: "section-label", text: "Where this came from" }));
      const source = el("div", { class: "source-card" }, [
        detail.source.title ? el("strong", { text: detail.source.title }) : null,
        detail.source.quote
          ? el("blockquote", { class: "source-quote", text: detail.source.quote })
          : null,
        detail.source.url
          ? el("a", {
              class: "text-sm", href: detail.source.url, target: "_blank", rel: "noopener noreferrer",
              text: detail.source.url,
            })
          : null,
        el("div", {
          class: "muted text-sm mt-1",
          text: `Collected ${(detail.source.collected_at || "").slice(0, 10)}`,
        }),
      ]);
      body.appendChild(source);
    }
    if (detail.detection_gap) {
      body.appendChild(el("div", { class: "notice notice-warn" },
        "No rule in the library covers this technique yet. A hunt on this hypothesis relies on " +
        "behavioural profiling alone, and the gap is worth closing."));
    }

    if (detail.threat_actors.length) {
      body.appendChild(el("div", { class: "section-label", text: "Associated threat actors" }));
      body.appendChild(el("div", { class: "row wrap" }, detail.threat_actors.map((actor) =>
        el("span", { class: "tag", text: actor }))));
    }

    body.appendChild(el("div", { class: "section-label", text: "Required data sources" }));
    if (detail.required_data_sources.length) {
      for (const source of detail.required_data_sources) body.appendChild(sourceCard(source, true));
    } else {
      body.appendChild(el("p", { class: "muted text-sm",
        text: "This hypothesis accepts any telemetry. Upload whatever logs you have available." }));
    }

    if (detail.optional_data_sources.length) {
      body.appendChild(el("div", { class: "section-label", text: "Recommended additional sources" }));
      for (const source of detail.optional_data_sources) body.appendChild(sourceCard(source, false));
    }

    body.appendChild(el("div", { class: "section-label", text: `Detections applied (${detail.rule_count})` }));
    body.appendChild(el("div", { class: "table-wrap" }, [
      el("table", { class: "data" }, [
        el("thead", {}, el("tr", {}, ["Detection", "Type", "Severity", "Technique"].map((h) => el("th", { text: h })))),
        el("tbody", {}, detail.rules.map((rule) =>
          el("tr", {}, [
            el("td", {}, [el("div", { style: "font-weight:600;font-size:13px", text: rule.name.replace(/\{[^}]+\}/g, "").trim() }),
                          el("div", { class: "mono muted", style: "font-size:11px", text: rule.id })]),
            el("td", { class: "text-sm", text: rule.detection_type }),
            el("td", {}, el("span", { class: `sev sev-${rule.severity}`, text: rule.severity })),
            el("td", { class: "text-sm muted", text: rule.mitre_technique_id || "" }),
          ])
        )),
      ]),
    ]));

    body.appendChild(el("div", { class: "section-label", text: "Expected findings" }));
    body.appendChild(el("ul", { style: "padding-left:18px;color:var(--slate);font-size:13.5px;line-height:1.8" },
      detail.expected_findings.map((finding) => el("li", { text: finding }))));

    body.appendChild(el("div", { class: "row mt-3" }, [
      el("button", {
        class: "btn",
        onclick: () => {
          backdrop.remove();
          navigate(`#/hunt/new?h=${encodeURIComponent(detail.id)}`);
        },
      }, "Start a hunt with this hypothesis"),
      el("button", { class: "btn btn-ghost", onclick: () => backdrop.remove() }, "Close"),
    ]));
    drawer.appendChild(body);
  }

  function sourceCard(source, required) {
    return el("div", { class: `source-item ${required ? "required" : "optional"}` }, [
      el("h4", {}, [
        el("span", { text: source.name }),
        el("span", { class: `tag ${required ? "tag-green" : ""}`, text: required ? "required" : "optional" }),
      ]),
      el("p", { text: source.description }),
      el("div", { class: "source-formats" }, source.formats.map((format) =>
        el("span", { class: "tag", text: format }))),
      el("div", { class: "source-hint", text: source.collection_hint }),
      el("div", { class: "mono muted mt-1", style: "font-size:11px", text: `Example files: ${source.examples.join(", ")}` }),
    ]);
  }

  draw();
}
