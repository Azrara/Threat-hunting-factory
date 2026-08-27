import { api } from "../api.js";
import {
  clear, el, emptyState, formatBytes, formatDate, formatNumber, relativeTime,
  spinner, statusBadge, toast,
} from "../ui.js";

export async function renderHunts(root, navigate) {
  clear(root).appendChild(spinner("Loading hunts"));
  let payload;
  try {
    payload = await api.hunts({ limit: 200 });
  } catch (error) {
    clear(root).appendChild(emptyState("Hunts unavailable", error.message));
    return;
  }

  let filter = "all";
  const body = el("tbody");
  const wrapper = el("section", { class: "card" }, [
    el("div", { class: "card-head" }, [
      el("div", {}, [
        el("h2", { text: "Hunt history" }),
        el("div", { class: "muted text-sm mt-1", text: `${payload.total} analyses in this workspace` }),
      ]),
      el("button", { class: "btn", onclick: () => navigate("#/hunt/new") }, "New hunt"),
    ]),
    el("div", { class: "card-body", style: "padding-top:12px" }, [
      el("div", { class: "filters" }, ["all", "completed", "running", "pending", "failed"].map((key) =>
        el("button", {
          class: `chip ${key === filter ? "active" : ""}`, dataset: { key },
          text: key === "all" ? "All" : key.charAt(0).toUpperCase() + key.slice(1),
          onclick: (event) => {
            filter = key;
            event.target.parentElement.querySelectorAll(".chip").forEach((chip) =>
              chip.classList.toggle("active", chip.dataset.key === key));
            fill();
          },
        })
      )),
      el("div", { class: "table-wrap" }, [
        el("table", { class: "data" }, [
          el("thead", {}, el("tr", {},
            ["Hunt", "Hypothesis", "Evidence", "Status", "Observations", "Risk", "Created", ""]
              .map((label) => el("th", { text: label })))),
          body,
        ]),
      ]),
    ]),
  ]);

  clear(root).appendChild(wrapper);
  fill();

  function fill() {
    clear(body);
    const rows = payload.items.filter((hunt) => filter === "all" || hunt.status === filter);
    if (!rows.length) {
      body.appendChild(el("tr", {}, el("td", { colspan: "8" },
        emptyState("No hunts to show", "Start a new hunt to populate this list.",
          el("button", { class: "btn mt-2", onclick: () => navigate("#/hunt/new") }, "New hunt")))));
      return;
    }
    for (const hunt of rows) body.appendChild(rowFor(hunt));
  }

  function rowFor(hunt) {
    const open = () => {
      if (hunt.status === "completed") navigate(`#/report/${hunt.id}`);
      else if (hunt.status === "failed") toast(hunt.error || "The analysis failed", "error");
      else toast(`${hunt.stage} (${hunt.progress}%)`);
    };
    return el("tr", { class: "clickable" }, [
      el("td", { onclick: open }, [
        el("strong", { text: hunt.title || hunt.hypothesis_name }),
        el("div", { class: "mono muted", style: "font-size:11px", text: hunt.id.slice(0, 12) }),
      ]),
      el("td", { class: "text-sm muted truncate", style: "max-width:240px", title: hunt.hypothesis_name, onclick: open,
        text: hunt.hypothesis_name }),
      el("td", { class: "text-sm", onclick: open }, [
        el("div", { class: "truncate", style: "max-width:190px", title: hunt.archive_name, text: hunt.archive_name }),
        el("div", { class: "muted", style: "font-size:11.5px",
          text: `${formatBytes(hunt.archive_bytes)} | ${formatNumber(hunt.events_parsed)} records` }),
      ]),
      el("td", { onclick: open }, [
        statusBadge(hunt.status),
        hunt.status === "running" || hunt.status === "pending"
          ? el("div", { class: "progress mt-1", style: "width:90px" }, [el("span", { style: `width:${hunt.progress}%` })])
          : null,
      ]),
      el("td", { onclick: open, text: formatNumber(hunt.observation_count) }),
      el("td", { onclick: open }, hunt.status === "completed"
        ? el("span", { class: "tag tag-dark", text: `${hunt.risk_score.toFixed(0)}/100` })
        : el("span", { class: "muted", text: "-" })),
      el("td", { class: "muted text-sm nowrap", title: formatDate(hunt.created_at), onclick: open,
        text: relativeTime(hunt.created_at) }),
      el("td", {}, el("div", { class: "row" }, [
        hunt.status === "completed"
          ? el("button", { class: "btn btn-ghost btn-sm", onclick: (event) => {
              event.stopPropagation();
              api.download(`/api/hunts/${hunt.id}/report.pdf`, "report.pdf")
                .then(() => toast("Report downloaded"))
                .catch((error) => toast(error.message, "error"));
            } }, "PDF")
          : null,
        el("button", { class: "btn btn-danger btn-sm", onclick: async (event) => {
            event.stopPropagation();
            if (!window.confirm("Delete this hunt and every observation it produced?")) return;
            try {
              await api.deleteHunt(hunt.id);
              payload.items = payload.items.filter((item) => item.id !== hunt.id);
              payload.total -= 1;
              fill();
              toast("Hunt deleted");
            } catch (error) {
              toast(error.message, "error");
            }
          } }, "Delete"),
      ])),
    ]);
  }
}
