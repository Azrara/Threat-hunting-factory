// The review queue for hypotheses derived from public reporting.
//
// Nothing published itself, so this page is where a candidate becomes part of the
// catalogue. Everything needed to decide is on the card: the statement, the
// technique and tactic, the telemetry it needs, the detections it would run, and
// the passage of the article that produced it.

import { api } from "../api.js";
import { clear, el, emptyState, spinner, toast } from "../ui.js";

const STATUSES = [
  ["review", "Awaiting review"],
  ["published", "Published"],
  ["rejected", "Rejected"],
  ["all", "Everything"],
];

export async function renderReview(root) {
  let status = "review";
  const list = el("div", { class: "queue-grid" });
  const filters = el("div", { class: "filters" });
  const summary = el("div", { class: "muted text-sm mb-2" });

  clear(root);
  root.appendChild(filters);
  root.appendChild(summary);
  root.appendChild(list);
  await load();

  async function load() {
    clear(list).appendChild(spinner("Loading the review queue"));
    let payload;
    try {
      payload = await api.reviewQueue(status);
    } catch (error) {
      clear(list).appendChild(emptyState("Queue unavailable", error.message));
      return;
    }
    clear(filters);
    for (const [key, label] of STATUSES) {
      const count = payload.counts[key];
      filters.appendChild(el("button", {
        class: `chip ${key === status ? "active" : ""}`,
        text: count === undefined ? label : `${label} (${count})`,
        onclick: () => {
          status = key;
          load();
        },
      }));
    }
    summary.textContent =
      `Validated against MITRE ATT&CK ${payload.attack_version}. The tactic, the detections and the ` +
      `priority are derived by the platform, not taken from the model.`;
    clear(list);
    if (!payload.items.length) {
      list.appendChild(emptyState(
        "Nothing here",
        status === "review"
          ? "The collector has proposed no hypothesis yet, or everything has been reviewed."
          : "No candidate has that status."));
      return;
    }
    for (const item of payload.items) list.appendChild(cardFor(item));
  }

  function cardFor(item) {
    const ready = item.quality === "ready";
    const pending = item.status === "review";
    const actions = el("div", { class: "row wrap" });
    if (pending) {
      actions.appendChild(el("button", {
        class: "btn btn-sm",
        disabled: !ready,
        title: ready ? "" : "This candidate did not pass every check",
        onclick: async (event) => {
          event.target.disabled = true;
          try {
            await api.publishCandidate(item.id);
            toast("Published to the catalogue");
            load();
          } catch (error) {
            toast(error.message, "error");
            event.target.disabled = false;
          }
        },
      }, "Publish"));
      actions.appendChild(el("button", {
        class: "btn btn-ghost btn-sm",
        onclick: async (event) => {
          event.target.disabled = true;
          try {
            await api.rejectCandidate(item.id);
            toast("Rejected");
            load();
          } catch (error) {
            toast(error.message, "error");
            event.target.disabled = false;
          }
        },
      }, "Reject"));
    } else {
      actions.appendChild(el("span", { class: "muted text-sm", text: `Status: ${item.status}` }));
    }

    return el("article", { class: `queue-card ${ready ? "ready" : "needs-attention"}` }, [
      el("div", { class: "row-between wrap" }, [
        el("div", { class: "row wrap" }, [
          el("span", { class: `tag ${ready ? "tag-green" : ""}`, text: ready ? "Ready" : "Needs attention" }),
          el("span", { class: "tag", text: item.family === "cti" ? "Threat intelligence" : "Technique" }),
          el("span", { class: "tag", text: `Priority ${item.priority}` }),
        ]),
        el("span", { class: "muted text-sm", text: (item.created_at || "").slice(0, 10) }),
      ]),
      el("h3", { class: "mb-0", text: item.name }),
      el("p", { class: "mb-0", text: item.statement }),
      el("div", { class: "row wrap" }, [
        item.mitre_technique_id
          ? el("a", {
              class: "tag tag-dark", href: item.attack_url, target: "_blank", rel: "noopener noreferrer",
              text: `${item.mitre_technique_id} ${item.mitre_technique}`,
            })
          : el("span", { class: "tag", text: "No technique" }),
        item.mitre_tactic ? el("span", { class: "tag", text: item.mitre_tactic }) : null,
        el("span", {
          class: `tag ${item.rule_count ? "tag-green" : ""}`,
          text: item.rule_count ? `${item.rule_count} detections` : "Detection gap",
        }),
        ...item.required_data_sources.map((source) => el("span", { class: "tag", text: source.name })),
      ]),
      item.gate_failures.length
        ? el("ul", { class: "queue-gates" }, item.gate_failures.map((reason) => el("li", { text: reason })))
        : null,
      item.source_url || item.source_quote
        ? el("div", { class: "source-card" }, [
            item.source_title ? el("strong", { text: item.source_title }) : null,
            item.source_quote ? el("blockquote", { class: "source-quote", text: item.source_quote }) : null,
            item.source_url
              ? el("a", {
                  class: "text-sm", href: item.source_url, target: "_blank", rel: "noopener noreferrer",
                  text: item.source_url,
                })
              : null,
          ])
        : null,
      actions,
    ]);
  }
}
