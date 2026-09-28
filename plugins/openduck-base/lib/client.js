window.__ModuleLoader__.load({
  id: '@openduck/openduck-base',
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
var __create = Object.create;
var __getProtoOf = Object.getPrototypeOf;
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __hasOwnProp = Object.prototype.hasOwnProperty;
function __accessProp(key) {
  return this[key];
}
var __toESMCache_node;
var __toESMCache_esm;
var __toESM = (mod, isNodeMode, target) => {
  var canCache = mod != null && typeof mod === "object";
  if (canCache) {
    var cache = isNodeMode ? __toESMCache_node ??= new WeakMap : __toESMCache_esm ??= new WeakMap;
    var cached = cache.get(mod);
    if (cached)
      return cached;
  }
  target = mod != null ? __create(__getProtoOf(mod)) : {};
  const to = isNodeMode || !mod || !mod.__esModule || !__hasOwnProp.call(mod, "default") ? __defProp(target, "default", { value: mod, enumerable: true }) : target;
  if (mod && typeof mod === "object" || typeof mod === "function") {
    for (let key of __getOwnPropNames(mod))
      if (!__hasOwnProp.call(to, key))
        __defProp(to, key, {
          get: __accessProp.bind(mod, key),
          enumerable: true
        });
  }
  if (canCache)
    cache.set(mod, to);
  return to;
};
var __toCommonJS = (from) => {
  var entry = (__moduleCache ??= new WeakMap).get(from), desc;
  if (entry)
    return entry;
  entry = __defProp({}, "__esModule", { value: true });
  if (from && typeof from === "object" || typeof from === "function") {
    for (var key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(entry, key))
        __defProp(entry, key, {
          get: __accessProp.bind(from, key),
          enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
        });
  }
  __moduleCache.set(from, entry);
  return entry;
};
var __moduleCache;
var __returnValue = (v) => v;
function __exportSetter(name, newValue) {
  this[name] = __returnValue.bind(null, newValue);
}
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, {
      get: all[name],
      enumerable: true,
      configurable: true,
      set: __exportSetter.bind(all, name)
    });
};

// src/client/index.tsx
var exports_client = {};
__export(exports_client, {
  NativeButton: () => NativeButton,
  apply: () => apply,
  inject: () => inject
});
module.exports = __toCommonJS(exports_client);
var import_dsh_client_ui_primitives4 = require("@deepseek-ai/dsh-client-ui-primitives");
var import_react4 = __toESM(require("react"), 1);

// src/client/OpenDuckSettingsCard.tsx
var import_react = __toESM(require("react"), 1);
var import_dsh_client_ui_primitives = require("@deepseek-ai/dsh-client-ui-primitives");

// src/client/settings-save.js
function normalized(projects) {
  return projects.map((project) => ({ root: project.root, displayName: project.displayName ?? "" }));
}
function normalizedCliRoot(value) {
  return { enabled: value.enabled === true, cwd: value.cwd ?? "", models: { codex: value.models?.codex ?? [], claude: value.models?.claude ?? [], kimi: value.models?.kimi ?? [] } };
}
async function saveAcceptedHistory(scope, projects) {
  await scope.set("history", { projects });
  const accepted = scope.getSnapshot().value.history?.projects ?? [];
  return JSON.stringify(normalized(accepted)) === JSON.stringify(normalized(projects));
}
async function saveAcceptedCliRoot(scope, cliRoot) {
  await scope.set("cliRoot", cliRoot);
  return JSON.stringify(normalizedCliRoot(scope.getSnapshot().value.cliRoot ?? {})) === JSON.stringify(normalizedCliRoot(cliRoot));
}

// src/client/OpenDuckSettingsCard.tsx
var rootIsValid = (root) => /^\/(?:[^/\0]+\/?)*$/.test(root) && !root.includes("/../") && !root.endsWith("/..");
var cliRootOf = (value) => ({ enabled: value?.enabled === true, cwd: value?.cwd ?? "", models: { codex: value?.models?.codex ?? [], claude: value?.models?.claude ?? [], kimi: value?.models?.kimi ?? [] } });
var OpenDuckSettingsCard = ({ scope }) => {
  const snapshot = import_react.useSyncExternalStore(scope.subscribe.bind(scope), scope.getSnapshot.bind(scope));
  const [root, setRoot] = import_react.useState("");
  const [pending, setPending] = import_react.useState(false);
  const [error, setError] = import_react.useState("");
  const projects = snapshot.value.history?.projects ?? [];
  const persistedCli = cliRootOf(snapshot.value.cliRoot);
  const [cliDraft, setCliDraft] = import_react.useState(persistedCli);
  const [cliDirty, setCliDirty] = import_react.useState(false);
  const writable = snapshot.writable !== false;
  import_react.useEffect(() => {
    if (!cliDirty)
      setCliDraft(persistedCli);
  }, [snapshot.value.cliRoot, cliDirty]);
  import_react.useEffect(() => {
    if (root && projects.some((project) => project.root === root.trim())) {
      setRoot("");
      setPending(false);
      setError("");
    }
  }, [projects, root]);
  const save = async (next) => {
    if (!writable) {
      setError("This settings source is read-only.");
      return;
    }
    setPending(true);
    setError("");
    try {
      if (!await saveAcceptedHistory(scope, next))
        throw new Error("settings snapshot did not accept history");
      setPending(false);
    } catch {
      setPending(false);
      setError("DSH rejected this history configuration. The project directory must exist and be canonical.");
    }
  };
  const saveCli = async () => {
    if (!writable) {
      setError("This settings source is read-only.");
      return;
    }
    setPending(true);
    setError("");
    try {
      if (!await saveAcceptedCliRoot(scope, cliDraft))
        throw new Error("settings snapshot did not accept CLI root chat");
      setCliDirty(false);
      setPending(false);
    } catch {
      setPending(false);
      setError("DSH rejected CLI root-chat settings. Choose an existing canonical workspace and at least one explicit model.");
    }
  };
  const setCli = (next) => {
    setCliDraft(next);
    setCliDirty(true);
  };
  const addProject = () => {
    const candidate = root.trim();
    if (!rootIsValid(candidate)) {
      setError("Enter an absolute canonical project directory.");
      return;
    }
    if (projects.some((project) => project.root === candidate)) {
      setError("This project is already configured.");
      return;
    }
    save([...projects, { root: candidate }]);
  };
  const removeProject = (candidate) => {
    save(projects.filter((project) => project.root !== candidate));
  };
  return /* @__PURE__ */ import_react.default.createElement("section", null, /* @__PURE__ */ import_react.default.createElement("h2", null, "OpenDuck connections"), /* @__PURE__ */ import_react.default.createElement("p", null, "Connect configured CLI subscriptions in a local terminal, then restart DSH."), /* @__PURE__ */ import_react.default.createElement("ul", null, /* @__PURE__ */ import_react.default.createElement("li", null, "Codex: ", /* @__PURE__ */ import_react.default.createElement("code", null, "make connect-codex")), /* @__PURE__ */ import_react.default.createElement("li", null, "Claude: ", /* @__PURE__ */ import_react.default.createElement("code", null, "make connect-claude")), /* @__PURE__ */ import_react.default.createElement("li", null, "Kimi ACP: ", /* @__PURE__ */ import_react.default.createElement("code", null, "make connect-kimi")), /* @__PURE__ */ import_react.default.createElement("li", null, "Computer MCP: ", /* @__PURE__ */ import_react.default.createElement("code", null, "make connect-computer"))), /* @__PURE__ */ import_react.default.createElement("p", null, "Use ", /* @__PURE__ */ import_react.default.createElement("code", null, "make doctor"), " for installed-provider readiness."), /* @__PURE__ */ import_react.default.createElement("h2", null, "CLI root chat"), /* @__PURE__ */ import_react.default.createElement("p", null, "Use ", /* @__PURE__ */ import_react.default.createElement("code", null, "make connect-cli-chat"), ", configure an explicit workspace and model allowlist, save this section, then restart DSH. This fixed workspace applies to every CLI root-chat turn. Root chat is text-only: DSH host-tool schemas are dropped and DSH tools cannot run in this mode."), /* @__PURE__ */ import_react.default.createElement("label", null, /* @__PURE__ */ import_react.default.createElement("input", {
    type: "checkbox",
    checked: cliDraft.enabled,
    disabled: !writable || pending,
    onChange: (event) => setCli({ ...cliDraft, enabled: event.target.checked })
  }), " Enable CLI root chat"), /* @__PURE__ */ import_react.default.createElement("label", null, "Workspace directory ", /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Input, {
    value: cliDraft.cwd,
    disabled: !writable || pending,
    onChange: (event) => setCli({ ...cliDraft, cwd: event.target.value }),
    placeholder: "/canonical/project"
  })), /* @__PURE__ */ import_react.default.createElement("label", null, "Codex model ", /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Input, {
    value: cliDraft.models.codex[0] ?? "",
    disabled: !writable || pending,
    onChange: (event) => setCli({ ...cliDraft, models: { ...cliDraft.models, codex: event.target.value ? [event.target.value] : [] } }),
    placeholder: "default or installed CLI model id"
  })), /* @__PURE__ */ import_react.default.createElement("label", null, "Claude model ", /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Input, {
    value: cliDraft.models.claude[0] ?? "",
    disabled: !writable || pending,
    onChange: (event) => setCli({ ...cliDraft, models: { ...cliDraft.models, claude: event.target.value ? [event.target.value] : [] } }),
    placeholder: "default or installed CLI model id"
  })), /* @__PURE__ */ import_react.default.createElement("label", null, "Kimi route label ", /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Input, {
    value: cliDraft.models.kimi[0] ?? "",
    disabled: !writable || pending,
    onChange: (event) => setCli({ ...cliDraft, models: { ...cliDraft.models, kimi: event.target.value ? [event.target.value] : [] } }),
    placeholder: "default (Kimi ACP configured default)"
  })), /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Button, {
    disabled: !writable || pending || !cliDirty,
    onClick: () => {
      saveCli();
    }
  }, "Save CLI root chat"), /* @__PURE__ */ import_react.default.createElement("h2", null, "External history projects"), /* @__PURE__ */ import_react.default.createElement("p", null, "Only exact existing project directories listed here can be queried by the read-only history viewer."), snapshot.status && snapshot.status !== "ready" && /* @__PURE__ */ import_react.default.createElement("p", {
    role: "status"
  }, "Settings are ", snapshot.status, "."), !writable && /* @__PURE__ */ import_react.default.createElement("p", {
    role: "status"
  }, "This settings source is read-only."), /* @__PURE__ */ import_react.default.createElement("ul", null, projects.map((project) => /* @__PURE__ */ import_react.default.createElement("li", {
    key: project.root
  }, project.displayName || project.root, " ", /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Button, {
    disabled: !writable || pending,
    onClick: () => removeProject(project.root)
  }, "Remove")))), /* @__PURE__ */ import_react.default.createElement("label", null, "Project directory ", /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Input, {
    value: root,
    disabled: !writable || pending,
    onChange: (event) => {
      setRoot(event.target.value);
      setError("");
    },
    placeholder: "/absolute/project"
  })), /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Button, {
    onClick: addProject,
    disabled: !writable || pending || !root.trim()
  }, "Add project"), pending && /* @__PURE__ */ import_react.default.createElement("p", {
    role: "status"
  }, "Saving configuration…"), error && /* @__PURE__ */ import_react.default.createElement("p", {
    role: "alert"
  }, error));
};

// src/client/HistorySidebarAction.tsx
var import_react3 = __toESM(require("react"), 1);
var import_dsh_client_ui_primitives3 = require("@deepseek-ai/dsh-client-ui-primitives");

// src/client/HistoryViewer.tsx
var import_react2 = __toESM(require("react"), 1);
var import_dsh_client_ui_primitives2 = require("@deepseek-ai/dsh-client-ui-primitives");
var providers = ["codex", "claude", "kimi"];
function page(value, valid) {
  if (value === null || typeof value !== "object" || !Array.isArray(value.items))
    return;
  const raw = value.items;
  if (!raw.every(valid))
    return;
  const cursor = value.nextCursor;
  return { items: raw, nextCursor: typeof cursor === "string" ? cursor : null };
}
var validProject = (item) => Boolean(item && typeof item === "object" && typeof item.id === "string" && typeof item.displayName === "string");
var validSession = (item) => Boolean(item && typeof item === "object" && typeof item.sessionId === "string");
var validMessage = (item) => Boolean(item && typeof item === "object" && typeof item.id === "string" && (item.role === "user" || item.role === "assistant") && typeof item.text === "string");
var HistoryViewer = ({ rpc }) => {
  const [projects, setProjects] = import_react2.useState([]);
  const [projectId, setProjectId] = import_react2.useState("");
  const [provider, setProvider] = import_react2.useState("codex");
  const [sessions, setSessions] = import_react2.useState([]);
  const [sessionCursor, setSessionCursor] = import_react2.useState(null);
  const [messages, setMessages] = import_react2.useState([]);
  const [messageCursor, setMessageCursor] = import_react2.useState(null);
  const [selectedSession, setSelectedSession] = import_react2.useState("");
  const [loading, setLoading] = import_react2.useState("projects");
  const [error, setError] = import_react2.useState("");
  const requestId = import_react2.useRef(0);
  const resetHistory = () => {
    setSessions([]);
    setSessionCursor(null);
    setMessages([]);
    setMessageCursor(null);
    setSelectedSession("");
    setError("");
  };
  const loadProjects = import_react2.useCallback(async () => {
    const id = ++requestId.current;
    setLoading("projects");
    setError("");
    try {
      const result = await rpc.call("/openduck-history", "projects", {});
      const resultPage = page(result.value, validProject);
      if (!result.ok || !resultPage || id !== requestId.current)
        throw new Error;
      setProjects(resultPage.items);
      setProjectId((current) => resultPage.items.some((project) => project.id === current) ? current : resultPage.items[0]?.id ?? "");
      resetHistory();
    } catch {
      if (id === requestId.current)
        setError("History is unavailable.");
    } finally {
      if (id === requestId.current)
        setLoading("");
    }
  }, [rpc]);
  import_react2.useEffect(() => {
    loadProjects();
  }, [loadProjects]);
  const loadSessions = async (cursor) => {
    if (!projectId)
      return;
    const id = ++requestId.current;
    setLoading("sessions");
    setError("");
    try {
      const result = await rpc.call("/openduck-history", "sessions", { projectId, provider, limit: 25, ...cursor ? { cursor } : {} });
      const resultPage = page(result.value, validSession);
      if (!result.ok || !resultPage || id !== requestId.current)
        throw new Error;
      setSessions((current) => cursor ? [...current, ...resultPage.items] : resultPage.items);
      setSessionCursor(resultPage.nextCursor);
      setMessages([]);
      setMessageCursor(null);
      setSelectedSession("");
    } catch {
      if (id === requestId.current)
        setError("History is unavailable.");
    } finally {
      if (id === requestId.current)
        setLoading("");
    }
  };
  const loadMessages = async (sessionId, cursor) => {
    if (!projectId)
      return;
    const id = ++requestId.current;
    setLoading("messages");
    setError("");
    try {
      const result = await rpc.call("/openduck-history", "messages", { projectId, provider, sessionId, limit: 100, ...cursor ? { cursor } : {} });
      const resultPage = page(result.value, validMessage);
      if (!result.ok || !resultPage || id !== requestId.current)
        throw new Error;
      setMessages((current) => cursor ? [...current, ...resultPage.items] : resultPage.items);
      setMessageCursor(resultPage.nextCursor);
      setSelectedSession(sessionId);
    } catch {
      if (id === requestId.current)
        setError("History is unavailable.");
    } finally {
      if (id === requestId.current)
        setLoading("");
    }
  };
  const chooseProject = (value) => {
    setProjectId(value);
    requestId.current += 1;
    resetHistory();
  };
  const chooseProvider = (value) => {
    setProvider(value);
    requestId.current += 1;
    resetHistory();
  };
  return /* @__PURE__ */ import_react2.default.createElement("section", {
    style: { display: "grid", gap: 14, minWidth: 0 }
  }, /* @__PURE__ */ import_react2.default.createElement("div", {
    style: { display: "flex", flexWrap: "wrap", gap: 10, alignItems: "end" }
  }, /* @__PURE__ */ import_react2.default.createElement("label", {
    style: { display: "grid", gap: 4 }
  }, "Project ", /* @__PURE__ */ import_react2.default.createElement("select", {
    value: projectId,
    onChange: (event) => chooseProject(event.target.value),
    disabled: loading === "projects"
  }, projects.map((project) => /* @__PURE__ */ import_react2.default.createElement("option", {
    key: project.id,
    value: project.id
  }, project.displayName)))), /* @__PURE__ */ import_react2.default.createElement("label", {
    style: { display: "grid", gap: 4 }
  }, "Provider ", /* @__PURE__ */ import_react2.default.createElement("select", {
    value: provider,
    onChange: (event) => chooseProvider(event.target.value),
    disabled: loading === "projects"
  }, providers.map((item) => /* @__PURE__ */ import_react2.default.createElement("option", {
    key: item
  }, item)))), /* @__PURE__ */ import_react2.default.createElement(import_dsh_client_ui_primitives2.Button, {
    onClick: () => void loadProjects(),
    disabled: loading !== ""
  }, "Refresh projects"), /* @__PURE__ */ import_react2.default.createElement(import_dsh_client_ui_primitives2.Button, {
    onClick: () => void loadSessions(),
    disabled: !projectId || loading !== ""
  }, "Load sessions")), loading && /* @__PURE__ */ import_react2.default.createElement("p", {
    role: "status"
  }, "Loading ", loading, "…"), error && /* @__PURE__ */ import_react2.default.createElement("p", {
    role: "alert"
  }, error), !loading && !error && projects.length === 0 && /* @__PURE__ */ import_react2.default.createElement("p", {
    role: "status"
  }, "Add a project in OpenDuck settings to view history."), !loading && !error && projectId && sessions.length === 0 && /* @__PURE__ */ import_react2.default.createElement("p", {
    role: "status"
  }, "No sessions loaded."), sessions.length > 0 && /* @__PURE__ */ import_react2.default.createElement("div", null, /* @__PURE__ */ import_react2.default.createElement("h3", null, "Sessions"), /* @__PURE__ */ import_react2.default.createElement("div", {
    style: { display: "grid", gap: 8, maxHeight: 220, overflow: "auto" }
  }, sessions.map((session) => /* @__PURE__ */ import_react2.default.createElement("div", {
    key: session.sessionId,
    style: { display: "flex", gap: 8, alignItems: "baseline" }
  }, /* @__PURE__ */ import_react2.default.createElement(import_dsh_client_ui_primitives2.Button, {
    onClick: () => void loadMessages(session.sessionId),
    disabled: loading !== ""
  }, session.title || session.sessionId), /* @__PURE__ */ import_react2.default.createElement("span", {
    style: { overflowWrap: "anywhere" }
  }, session.preview || "")))), sessionCursor && /* @__PURE__ */ import_react2.default.createElement(import_dsh_client_ui_primitives2.Button, {
    onClick: () => void loadSessions(sessionCursor),
    disabled: loading !== ""
  }, "Load more sessions")), selectedSession && /* @__PURE__ */ import_react2.default.createElement("div", null, /* @__PURE__ */ import_react2.default.createElement("h3", null, "Messages"), !loading && messages.length === 0 && /* @__PURE__ */ import_react2.default.createElement("p", {
    role: "status"
  }, "No messages are available for this session."), /* @__PURE__ */ import_react2.default.createElement("ol", {
    style: { display: "grid", gap: 10, maxHeight: 360, overflow: "auto", paddingLeft: 22 }
  }, messages.map((message) => /* @__PURE__ */ import_react2.default.createElement("li", {
    key: message.id,
    style: { overflowWrap: "anywhere", whiteSpace: "pre-wrap" }
  }, /* @__PURE__ */ import_react2.default.createElement("strong", null, message.role === "user" ? "You" : "Assistant"), /* @__PURE__ */ import_react2.default.createElement("div", null, message.text)))), messageCursor && /* @__PURE__ */ import_react2.default.createElement(import_dsh_client_ui_primitives2.Button, {
    onClick: () => void loadMessages(selectedSession, messageCursor),
    disabled: loading !== ""
  }, "Load more messages")));
};

// src/client/HistorySidebarAction.tsx
var HistorySidebarAction = ({ rpc, wide }) => {
  const [open, setOpen] = import_react3.useState(false);
  return /* @__PURE__ */ import_react3.default.createElement(import_react3.default.Fragment, null, /* @__PURE__ */ import_react3.default.createElement(import_dsh_client_ui_primitives3.Button, {
    onClick: () => setOpen(true)
  }, wide ? "CLI history" : "History"), /* @__PURE__ */ import_react3.default.createElement(import_dsh_client_ui_primitives3.Modal, {
    open,
    onClose: () => setOpen(false),
    title: "CLI history",
    description: "Read-only external CLI sessions for configured projects.",
    className: "openduck-history-modal",
    contentClassName: "openduck-history-modal-content"
  }, /* @__PURE__ */ import_react3.default.createElement("style", null, `.openduck-history-modal{width:min(860px,calc(100vw - 32px));max-height:calc(100vh - 32px)}.openduck-history-modal-content{min-height:0;overflow:auto}`), /* @__PURE__ */ import_react3.default.createElement(HistoryViewer, {
    rpc
  })));
};

// src/client/index.tsx
var inject = ["slots", "connection", "settingsScope"];
var apply = (ctx) => {
  ctx.slots.inject("settings.plugin.item", () => ctx.slots.register({
    name: "settings.plugin.item",
    key: "openduck",
    locale: "settings.plugins",
    inject: () => ({})
  }, () => /* @__PURE__ */ import_react4.default.createElement(OpenDuckSettingsCard, {
    scope: ctx.settingsScope.bind({ namespace: "openduck" })
  })));
  ctx.slots.inject("sidebar.footer.action", () => ctx.slots.register({
    name: "sidebar.footer.action",
    id: "openduck-cli-history",
    locale: "settings.plugins",
    inject: () => ({})
  }, ({ wide }) => /* @__PURE__ */ import_react4.default.createElement(HistorySidebarAction, {
    rpc: ctx.connection.rpc,
    wide: wide === true
  })));
};
var NativeButton = import_dsh_client_ui_primitives4.Button;

    return module.exports;
  },
})
