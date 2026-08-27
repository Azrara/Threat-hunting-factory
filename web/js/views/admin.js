import { api, auth } from "../api.js";
import { clear, el, emptyState, formatDate, relativeTime, spinner, toast } from "../ui.js";

export async function renderAdmin(root) {
  clear(root).appendChild(spinner("Loading workspace settings"));
  const session = auth.session || {};
  const isAdmin = (session.user || {}).role === "admin";

  let users;
  let workspace;
  let audit = { items: [] };
  try {
    [users, workspace] = await Promise.all([api.users(), api.workspace()]);
    if (isAdmin) audit = await api.audit().catch(() => ({ items: [] }));
  } catch (error) {
    clear(root).appendChild(emptyState("Settings unavailable", error.message));
    return;
  }

  clear(root);
  root.appendChild(el("div", { class: "grid grid-sidebar" }, [
    el("div", {}, [usersCard(), isAdmin ? auditCard() : null]),
    el("aside", {}, [workspaceCard(), isAdmin ? inviteCard() : null]),
  ]));

  function workspaceCard() {
    const tenant = workspace.tenant;
    return el("section", { class: "card mb-3" }, [
      el("div", { class: "card-head" }, [el("h3", { text: "Workspace" })]),
      el("div", { class: "card-body" }, [
        row("Name", tenant.name),
        row("Identifier", tenant.slug),
        row("Industry", tenant.industry || "not set"),
        row("Members", String(workspace.user_count)),
        row("Created", formatDate(tenant.created_at, false)),
        el("div", { class: "source-hint mt-2", text:
          "All hunts, observations and reports are scoped to this workspace. Members of other workspaces cannot see them." }),
      ]),
    ]);
  }

  function row(label, value) {
    return el("div", { class: "row-between", style: "padding:8px 0;border-bottom:1px solid var(--line-soft)" }, [
      el("span", { class: "muted text-sm", text: label }),
      el("span", { style: "font-weight:600;font-size:13.5px", text: value }),
    ]);
  }

  function usersCard() {
    const body = el("tbody");
    const card = el("section", { class: "card mb-3" }, [
      el("div", { class: "card-head" }, [
        el("div", {}, [
          el("h2", { text: "Members" }),
          el("div", { class: "muted text-sm mt-1", text: `${users.total} user${users.total > 1 ? "s" : ""} in this workspace` }),
        ]),
      ]),
      el("div", { class: "table-wrap" }, [
        el("table", { class: "data" }, [
          el("thead", {}, el("tr", {}, ["Member", "Role", "Status", "Last sign in", ""].map((h) => el("th", { text: h })))),
          body,
        ]),
      ]),
    ]);

    function fill() {
      clear(body);
      for (const user of users.items) {
        const isSelf = user.id === (session.user || {}).id;
        body.appendChild(el("tr", {}, [
          el("td", {}, [
            el("strong", { text: user.full_name || user.email }),
            el("div", { class: "muted text-sm", text: user.email }),
          ]),
          el("td", {}, isAdmin && !isSelf
            ? el("select", {
                class: "input", style: "max-width:130px;padding:6px 8px",
                onchange: async (event) => {
                  try {
                    await api.updateUser(user.id, { role: event.target.value });
                    user.role = event.target.value;
                    toast("Role updated");
                  } catch (error) {
                    toast(error.message, "error");
                    event.target.value = user.role;
                  }
                },
              }, ["admin", "analyst", "viewer"].map((role) =>
                el("option", { value: role, selected: role === user.role ? "selected" : null, text: role })))
            : el("span", { class: "tag", text: user.role })),
          el("td", {}, el("span", {
            class: `tag ${user.is_active ? "tag-green" : ""}`,
            text: user.is_active ? "active" : "disabled",
          })),
          el("td", { class: "muted text-sm", text: user.last_login_at ? relativeTime(user.last_login_at) : "never" }),
          el("td", {}, isAdmin && !isSelf
            ? el("div", { class: "row" }, [
                el("button", { class: "btn btn-ghost btn-sm", onclick: async () => {
                  try {
                    const updated = await api.updateUser(user.id, { is_active: !user.is_active });
                    Object.assign(user, updated);
                    fill();
                    toast(updated.is_active ? "Account enabled" : "Account disabled");
                  } catch (error) {
                    toast(error.message, "error");
                  }
                } }, user.is_active ? "Disable" : "Enable"),
                el("button", { class: "btn btn-danger btn-sm", onclick: async () => {
                  if (!window.confirm(`Remove ${user.email} from this workspace?`)) return;
                  try {
                    await api.deleteUser(user.id);
                    users.items = users.items.filter((item) => item.id !== user.id);
                    users.total -= 1;
                    fill();
                    toast("Member removed");
                  } catch (error) {
                    toast(error.message, "error");
                  }
                } }, "Remove"),
              ])
            : el("span", { class: "muted text-sm", text: isSelf ? "you" : "" })),
        ]));
      }
    }
    fill();
    card.fill = fill;
    usersCard.current = card;
    return card;
  }

  function inviteCard() {
    const error = el("div", { class: "auth-error hidden" });
    return el("section", { class: "card" }, [
      el("div", { class: "card-head" }, [el("h3", { text: "Add a member" })]),
      el("div", { class: "card-body" }, [
        error,
        el("form", {
          onsubmit: async (event) => {
            event.preventDefault();
            error.classList.add("hidden");
            const payload = Object.fromEntries(new FormData(event.target).entries());
            try {
              const created = await api.createUser(payload);
              users.items.push(created);
              users.total += 1;
              usersCard.current.fill();
              event.target.reset();
              toast(`${created.email} added`);
            } catch (err) {
              error.textContent = err.message;
              error.classList.remove("hidden");
            }
          },
        }, [
          field("Email address", "email", "email", "colleague@example.com"),
          field("Full name", "full_name", "text", "Jamie Cole"),
          field("Temporary password", "password", "password", ""),
          el("div", { class: "field" }, [
            el("label", { text: "Role" }),
            el("select", { class: "input", name: "role" }, [
              el("option", { value: "analyst", text: "Analyst, can run hunts" }),
              el("option", { value: "viewer", text: "Viewer, read only" }),
              el("option", { value: "admin", text: "Administrator" }),
            ]),
          ]),
          el("button", { class: "btn btn-block", type: "submit" }, "Add member"),
        ]),
      ]),
    ]);
  }

  function field(label, name, type, placeholder) {
    return el("div", { class: "field" }, [
      el("label", { text: label }),
      el("input", { class: "input", name, type, placeholder, required: "required",
        minlength: type === "password" ? "8" : null }),
    ]);
  }

  function auditCard() {
    return el("section", { class: "card" }, [
      el("div", { class: "card-head" }, [
        el("div", {}, [
          el("h2", { text: "Activity log" }),
          el("div", { class: "muted text-sm mt-1", text: "The last 200 actions recorded in this workspace" }),
        ]),
      ]),
      el("div", { class: "table-wrap", style: "max-height:420px;overflow-y:auto" }, [
        el("table", { class: "data" }, [
          el("thead", {}, el("tr", {}, ["Action", "Detail", "Member", "When"].map((h) => el("th", { text: h })))),
          el("tbody", {}, audit.items.length
            ? audit.items.map((entry) =>
                el("tr", {}, [
                  el("td", {}, el("span", { class: "tag", text: entry.action })),
                  el("td", { class: "mono text-sm truncate", style: "max-width:240px", text: entry.detail || "" }),
                  el("td", { class: "text-sm", text: entry.user || "" }),
                  el("td", { class: "muted text-sm nowrap", text: relativeTime(entry.created_at) }),
                ])
              )
            : [el("tr", {}, el("td", { colspan: "4" }, emptyState("No activity recorded", "Actions will appear here.")))]),
        ]),
      ]),
    ]);
  }
}
