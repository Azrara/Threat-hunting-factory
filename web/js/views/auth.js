import { api, auth } from "../api.js";
import { el, clear, toast } from "../ui.js";

const POINTS = [
  ["Hypothesis led", "Start from a threat intelligence scenario, a technique or a mathematical model rather than from an alert queue."],
  ["Any log, any format", "The engine identifies and normalises Windows, Linux, network, web, cloud and appliance logs automatically."],
  ["Evidence backed reporting", "Every observation carries the original log line, the cyber risk, the impact and the remediation."],
];

export function renderAuth(root, onSignedIn) {
  let mode = "login";
  let engine = { total: 0, mitre_techniques: 0 };

  api.health().then((data) => {
    engine = data.engine || engine;
    draw();
  }).catch(() => draw());

  function brandPanel() {
    return el("section", { class: "auth-brand" }, [
      el("h1", { html: 'Threat Hunting Factory<span class="dot">.</span>' }),
      el("p", {
        text:
          "An end to end platform for hypothesis driven threat hunting: choose the hypothesis, upload the evidence, " +
          "and receive a complete report with observations, risk, impact and recommendations.",
      }),
      el("div", { class: "auth-points" }, POINTS.map(([title, body]) =>
        el("div", { class: "auth-point" }, [
          el("span", { class: "bullet" }),
          el("div", {}, [el("strong", { text: title }), el("span", { text: body })]),
        ])
      )),
      el("div", { class: "auth-stats" }, [
        stat(engine.total || 0, "Detections"),
        stat(engine.mitre_techniques || 0, "ATT&CK techniques"),
        stat(26, "Hypotheses"),
      ]),
    ]);
  }

  function stat(value, label) {
    return el("div", { class: "auth-stat" }, [
      el("div", { class: "n", text: String(value) }),
      el("div", { class: "l", text: label }),
    ]);
  }

  function draw() {
    clear(root);
    root.appendChild(el("div", { class: "auth" }, [brandPanel(), formPanel()]));
  }

  function formPanel() {
    const error = el("div", { class: "auth-error hidden" });
    const submit = el("button", { class: "btn btn-block", type: "submit" },
      mode === "login" ? "Sign in" : "Create workspace");

    const fields = mode === "login"
      ? [
          field("Workspace identifier", "tenant_slug", "text", "demo", true),
          field("Email address", "email", "email", "analyst@demo.local", true),
          field("Password", "password", "password", "", true),
        ]
      : [
          field("Organisation name", "tenant_name", "text", "Contoso Group", true),
          field("Workspace identifier", "tenant_slug", "text", "contoso", true,
            "Lower case letters, digits and hyphens. Your team uses this to sign in."),
          field("Industry", "industry", "text", "Financial services", false),
          field("Your full name", "full_name", "text", "Alex Moreau", true),
          field("Email address", "email", "email", "alex@contoso.com", true),
          field("Password", "password", "password", "", true, "At least 8 characters."),
        ];

    const form = el("form", {
      onsubmit: async (event) => {
        event.preventDefault();
        error.classList.add("hidden");
        submit.disabled = true;
        submit.textContent = mode === "login" ? "Signing in ..." : "Creating workspace ...";
        const payload = Object.fromEntries(new FormData(event.target).entries());
        try {
          const result = mode === "login" ? await api.login(payload) : await api.register(payload);
          auth.save(result);
          toast(mode === "login" ? "Signed in" : "Workspace created");
          onSignedIn();
        } catch (err) {
          error.textContent = err.message;
          error.classList.remove("hidden");
          submit.disabled = false;
          submit.textContent = mode === "login" ? "Sign in" : "Create workspace";
        }
      },
    }, [...fields, submit]);

    return el("section", { class: "auth-form-wrap" }, [
      el("div", { class: "auth-form" }, [
        el("h2", { text: mode === "login" ? "Sign in to your workspace" : "Create a new workspace" }),
        el("p", {
          class: "lead",
          text: mode === "login"
            ? "Access is scoped per workspace and per user."
            : "You will become the administrator of the new workspace.",
        }),
        error,
        form,
        el("div", { class: "auth-switch" }, [
          mode === "login" ? "No workspace yet? " : "Already have a workspace? ",
          el("a", {
            text: mode === "login" ? "Create one" : "Sign in",
            onclick: () => {
              mode = mode === "login" ? "register" : "login";
              draw();
            },
          }),
        ]),
        mode === "login"
          ? el("div", { class: "demo-box", html:
              'Demonstration workspace: <strong>demo</strong> | <strong>analyst@demo.local</strong> | ' +
              '<strong>HuntFactory2026</strong>' })
          : null,
      ]),
    ]);
  }

  function field(label, name, type, placeholder, required, hint) {
    return el("div", { class: "field" }, [
      el("label", { for: `f-${name}`, text: label }),
      el("input", {
        class: "input", id: `f-${name}`, name, type, placeholder,
        required: required ? "required" : null,
        autocomplete: type === "password" ? "current-password" : "on",
      }),
      hint ? el("div", { class: "hint", text: hint }) : null,
    ]);
  }

  draw();
}
