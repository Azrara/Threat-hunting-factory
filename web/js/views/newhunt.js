import { api } from "../api.js";
import { FAMILY_LABELS, clear, el, emptyState, formatBytes, spinner, toast } from "../ui.js";

export async function renderNewHunt(root, navigate, params) {
  const preselected = params.get("h");
  clear(root).appendChild(spinner("Preparing the hunt wizard"));

  let catalogue;
  try {
    catalogue = await api.hypotheses();
  } catch (error) {
    clear(root).appendChild(emptyState("Catalogue unavailable", error.message));
    return;
  }

  const state = {
    step: preselected ? 1 : 0,
    hypothesis: preselected ? catalogue.items.find((item) => item.id === preselected) || null : null,
    detail: null,
    file: null,
    title: "",
    hunt: null,
    poller: null,
  };
  if (state.hypothesis && !state.detail) {
    state.detail = await api.hypothesis(state.hypothesis.id).catch(() => null);
  }

  const host = el("div");
  clear(root).appendChild(host);
  draw();

  function stepper() {
    const labels = ["Choose a hypothesis", "Prepare the data", "Upload evidence", "Analyse"];
    return el("div", { class: "steps" }, labels.map((label, index) =>
      el("div", {
        class: `step ${index === state.step ? "active" : ""} ${index < state.step ? "done" : ""}`,
      }, [
        el("span", { class: "n", text: index < state.step ? "✓" : String(index + 1) }),
        el("span", { text: label }),
      ])
    ));
  }

  function draw() {
    clear(host);
    host.appendChild(stepper());
    if (state.step === 0) host.appendChild(chooseStep());
    else if (state.step === 1) host.appendChild(prepareStep());
    else if (state.step === 2) host.appendChild(uploadStep());
    else host.appendChild(runStep());
  }

  // ------------------------------------------------------------- step one
  function chooseStep() {
    const grid = el("div", { class: "hyp-grid" });
    let family = "all";
    const filters = el("div", { class: "filters" },
      ["all", "cti", "technique", "mathematical"].map((key) =>
        el("button", {
          class: `chip ${key === family ? "active" : ""}`, dataset: { family: key },
          text: key === "all" ? "All" : FAMILY_LABELS[key],
          onclick: () => {
            family = key;
            filters.querySelectorAll(".chip").forEach((chip) =>
              chip.classList.toggle("active", chip.dataset.family === key));
            fill();
          },
        })
      ));

    function fill() {
      clear(grid);
      catalogue.items
        .filter((item) => family === "all" || item.family === family)
        .forEach((item) => {
          grid.appendChild(el("article", {
            class: `hyp-card family-${item.family}`,
            onclick: async () => {
              state.hypothesis = item;
              state.detail = await api.hypothesis(item.id).catch(() => null);
              state.step = 1;
              draw();
            },
          }, [
            el("div", { class: "row-between" }, [
              el("span", { class: "tag", text: FAMILY_LABELS[item.family] }),
              el("span", { class: "tag", text: item.priority }),
            ]),
            el("h3", { text: item.name }),
            el("p", { text: item.summary }),
            el("div", { class: "hyp-meta" }, [
              el("span", { class: "tag tag-green", text: `${item.rule_count} detections` }),
              el("span", { class: "tag", text: `${item.techniques.length} techniques` }),
            ]),
          ]));
        });
    }
    fill();
    return el("div", {}, [
      el("h1", { class: "mb-1", text: "Select the hypothesis to explore" }),
      el("p", { class: "muted mb-3",
        text: "Each hypothesis defines the question, the telemetry it needs and the detections that will run." }),
      filters, grid,
    ]);
  }

  // ------------------------------------------------------------- step two
  function prepareStep() {
    const detail = state.detail || {};
    const required = detail.required_data_sources || [];
    const optional = detail.optional_data_sources || [];
    return el("div", { class: "grid grid-sidebar" }, [
      el("section", { class: "card" }, [
        el("div", { class: "card-head" }, [
          el("div", {}, [
            el("h2", { text: "Evidence required for this hypothesis" }),
            el("div", { class: "muted text-sm mt-1",
              text: "Collect the following logs, place them in one archive and upload it in the next step." }),
          ]),
        ]),
        el("div", { class: "card-body" }, [
          required.length
            ? el("div", {}, required.map((source) => sourceBlock(source, true)))
            : el("p", { class: "muted",
                text: "This hypothesis has no mandatory source. Upload any logs you have and the engine will apply everything it can." }),
          optional.length ? el("div", { class: "section-label", text: "Recommended additional sources" }) : null,
          ...optional.map((source) => sourceBlock(source, false)),
          el("div", { class: "section-label", text: "Accepted upload formats" }),
          el("p", { class: "text-sm muted", text:
            "A zip, tar or tar.gz archive containing any number of log files, or a single log file. " +
            "The engine detects JSON, NDJSON, CSV, TSV, syslog, Windows event XML and evtx, Sysmon, CEF, LEEF, " +
            "Zeek TSV, W3C extended, Apache and Nginx access logs, key value formats and free text automatically." }),
          el("div", { class: "row mt-3" }, [
            el("button", { class: "btn", onclick: () => { state.step = 2; draw(); } }, "Continue to upload"),
            el("button", { class: "btn btn-ghost", onclick: () => { state.step = 0; draw(); } }, "Change hypothesis"),
          ]),
        ]),
      ]),
      el("aside", { class: "card" }, [
        el("div", { class: "card-head" }, [el("h3", { text: "Selected hypothesis" })]),
        el("div", { class: "card-body" }, [
          el("span", { class: "tag tag-green mb-2", text: FAMILY_LABELS[detail.family] || "" }),
          el("h3", { class: "mb-2", text: detail.name || "" }),
          el("p", { class: "text-sm muted", text: detail.summary || "" }),
          el("div", { class: "section-label", text: "Detections applied" }),
          el("div", { class: "row wrap" }, [
            el("span", { class: "tag tag-dark", text: `${detail.rule_count || 0} rules` }),
            ...(detail.detection_types || []).map((type) => el("span", { class: "tag", text: type })),
          ]),
          el("div", { class: "section-label", text: "ATT&CK techniques" }),
          el("div", { class: "row wrap" }, (detail.techniques || []).slice(0, 14).map((technique) =>
            el("span", { class: "tag", text: technique }))),
        ]),
      ]),
    ]);
  }

  function sourceBlock(source, required) {
    return el("div", { class: `source-item ${required ? "required" : "optional"}` }, [
      el("h4", {}, [
        el("span", { text: source.name }),
        el("span", { class: `tag ${required ? "tag-green" : ""}`, text: required ? "required" : "optional" }),
      ]),
      el("p", { text: source.description }),
      el("div", { class: "source-formats" }, source.formats.map((f) => el("span", { class: "tag", text: f }))),
      el("div", { class: "source-hint", text: source.collection_hint }),
    ]);
  }

  // ----------------------------------------------------------- step three
  function uploadStep() {
    const input = el("input", {
      type: "file", class: "hidden",
      accept: ".zip,.gz,.tgz,.tar,.bz2,.xz,.log,.txt,.json,.jsonl,.ndjson,.csv,.tsv,.xml,.evtx,.cef,.leef,.eve",
      onchange: (event) => {
        state.file = event.target.files[0] || null;
        draw();
      },
    });

    const dropzone = el("div", {
      class: "dropzone",
      onclick: () => input.click(),
      ondragover: (event) => { event.preventDefault(); dropzone.classList.add("drag"); },
      ondragleave: () => dropzone.classList.remove("drag"),
      ondrop: (event) => {
        event.preventDefault();
        dropzone.classList.remove("drag");
        state.file = event.dataTransfer.files[0] || null;
        draw();
      },
    }, [
      el("div", { class: "icon", text: "⬆" }),
      el("h3", { text: "Drop the evidence archive here" }),
      el("p", { text: "or click to browse. Zip, tar, tar.gz or a single log file, up to 512 MB." }),
    ]);

    const progressBar = el("span", { style: "width:0%" });
    const progressWrap = el("div", { class: "progress mt-2 hidden" }, [progressBar]);
    const submit = el("button", {
      class: "btn", disabled: state.file ? null : "disabled",
      onclick: async () => {
        if (!state.file) return;
        submit.disabled = true;
        submit.textContent = "Uploading ...";
        progressWrap.classList.remove("hidden");
        const form = new FormData();
        form.append("hypothesis_id", state.hypothesis.id);
        form.append("title", state.title || state.hypothesis.name);
        form.append("file", state.file);
        try {
          state.hunt = await api.createHunt(form, (fraction) => {
            progressBar.style.width = `${Math.round(fraction * 100)}%`;
          });
          state.step = 3;
          draw();
          poll();
        } catch (error) {
          toast(error.message, "error");
          submit.disabled = false;
          submit.textContent = "Start the analysis";
          progressWrap.classList.add("hidden");
        }
      },
    }, "Start the analysis");

    return el("div", { class: "grid grid-sidebar" }, [
      el("section", { class: "card" }, [
        el("div", { class: "card-head" }, [
          el("div", {}, [
            el("h2", { text: "Upload the evidence archive" }),
            el("div", { class: "muted text-sm mt-1", text: "Everything stays inside your workspace." }),
          ]),
        ]),
        el("div", { class: "card-body" }, [
          el("div", { class: "field" }, [
            el("label", { text: "Hunt title" }),
            el("input", {
              class: "input", value: state.title, placeholder: state.hypothesis.name,
              oninput: (event) => { state.title = event.target.value; },
            }),
            el("div", { class: "hint", text: "Used on the report cover page. Defaults to the hypothesis name." }),
          ]),
          input,
          dropzone,
          state.file
            ? el("div", { class: "file-pill" }, [
                el("div", {}, [
                  el("strong", { text: state.file.name }),
                  el("div", { class: "meta", text: formatBytes(state.file.size) }),
                ]),
                el("button", { class: "btn btn-ghost btn-sm", onclick: () => { state.file = null; draw(); } }, "Remove"),
              ])
            : null,
          progressWrap,
          el("div", { class: "row mt-3" }, [
            submit,
            el("button", { class: "btn btn-ghost", onclick: () => { state.step = 1; draw(); } }, "Back"),
          ]),
        ]),
      ]),
      el("aside", { class: "card" }, [
        el("div", { class: "card-head" }, [el("h3", { text: "What happens next" })]),
        el("div", { class: "card-body text-sm" }, [
          el("ol", { style: "padding-left:18px;line-height:1.9;color:var(--slate)" }, [
            el("li", { text: "The archive is extracted with path and size protections." }),
            el("li", { text: "Every file is sniffed and matched to the best parser." }),
            el("li", { text: "Records are normalised into one common schema." }),
            el("li", { text: `${(state.detail || {}).rule_count || 0} detections and statistical models run over the data.` }),
            el("li", { text: "Observations are scored, ranked and written to the report." }),
          ]),
        ]),
      ]),
    ]);
  }

  // ------------------------------------------------------------ step four
  function runStep() {
    const hunt = state.hunt || {};
    const bar = el("span", { style: `width:${hunt.progress || 0}%` });
    return el("section", { class: "card" }, [
      el("div", { class: "card-body run-panel" }, [
        hunt.status === "failed" ? el("div", { class: "icon", text: "⚠" }) : el("div", { class: "spinner" }),
        el("div", { class: "pct", text: `${hunt.progress || 0}%` }),
        el("div", { class: "stage", text: hunt.stage || "Queued" }),
        el("p", { class: "muted text-sm", text: state.file ? state.file.name : hunt.archive_name || "" }),
        el("div", { class: "progress", style: "max-width:460px;margin:18px auto 0" }, [bar]),
        hunt.status === "failed"
          ? el("div", { class: "mt-3" }, [
              el("p", { class: "mono text-sm", style: "color:var(--critical)", text: hunt.error || "The analysis failed" }),
              el("button", { class: "btn btn-ghost", onclick: () => navigate("#/hunts") }, "Back to hunts"),
            ])
          : null,
      ]),
    ]);
  }

  async function poll() {
    if (state.poller) clearInterval(state.poller);
    state.poller = setInterval(async () => {
      try {
        const hunt = await api.hunt(state.hunt.id);
        state.hunt = hunt;
        if (state.step === 3) draw();
        if (hunt.status === "completed") {
          clearInterval(state.poller);
          state.poller = null;
          toast(`Analysis complete, ${hunt.observation_count} observations`);
          navigate(`#/report/${hunt.id}`);
        } else if (hunt.status === "failed") {
          clearInterval(state.poller);
          state.poller = null;
          toast("The analysis failed", "error");
        }
      } catch (error) {
        clearInterval(state.poller);
        state.poller = null;
        toast(error.message, "error");
      }
    }, 1200);
  }

  return () => {
    if (state.poller) clearInterval(state.poller);
  };
}
