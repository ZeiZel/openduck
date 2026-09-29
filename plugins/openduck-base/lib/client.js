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
var import_dsh_client_ui_primitives5 = require("@deepseek-ai/dsh-client-ui-primitives");
var import_react5 = __toESM(require("react"), 1);

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
  if (!await scope.set("history", { projects }))
    return false;
  const accepted = scope.getSnapshot().value?.history?.projects ?? [];
  return JSON.stringify(normalized(accepted)) === JSON.stringify(normalized(projects));
}
async function saveAcceptedCliRoot(scope, cliRoot) {
  if (!await scope.set("cliRoot", cliRoot))
    return false;
  return JSON.stringify(normalizedCliRoot(scope.getSnapshot().value?.cliRoot ?? {})) === JSON.stringify(normalizedCliRoot(cliRoot));
}

// src/client/OpenDuckSettingsCard.tsx
var rootIsValid = (root) => /^\/(?:[^/\0]+\/?)*$/.test(root) && !root.includes("/../") && !root.endsWith("/..");
var cliRootOf = (value) => ({ enabled: value?.enabled === true, cwd: value?.cwd ?? "", models: { codex: value?.models?.codex ?? [], claude: value?.models?.claude ?? [], kimi: value?.models?.kimi ?? [] } });
function statusItems(value) {
  if (value === null || typeof value !== "object" || !Array.isArray(value.items))
    return [];
  return value.items.filter((item) => Boolean(item && typeof item === "object" && ["codex", "claude", "kimi"].includes(item.provider) && typeof item.label === "string" && typeof item.installed === "boolean" && ["authenticated", "not-signed-in", "unknown"].includes(item.auth)));
}
var OpenDuckSettingsCard = ({ scope, rpc }) => {
  const snapshot = import_react.useSyncExternalStore(scope.subscribe.bind(scope), scope.getSnapshot.bind(scope));
  const [root, setRoot] = import_react.useState("");
  const [pending, setPending] = import_react.useState(false);
  const [error, setError] = import_react.useState("");
  const value = snapshot.value ?? {};
  const projects = value.history?.projects ?? [];
  const persistedCli = cliRootOf(value.cliRoot);
  const [cliDraft, setCliDraft] = import_react.useState(persistedCli);
  const [cliDirty, setCliDirty] = import_react.useState(false);
  const [providers, setProviders] = import_react.useState([]);
  const [providerBusy, setProviderBusy] = import_react.useState(false);
  const [providerError, setProviderError] = import_react.useState("");
  const writable = snapshot.writable !== false;
  import_react.useEffect(() => {
    if (!cliDirty)
      setCliDraft(persistedCli);
  }, [value.cliRoot, cliDirty]);
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
      setError("DSH rejected CLI root-chat settings.");
    }
  };
  const setCli = (next) => {
    setCliDraft(next);
    setCliDirty(true);
  };
  const refreshProviders = async () => {
    setProviderBusy(true);
    setProviderError("");
    try {
      const response = await rpc.call("/api", "openduck-cli/status", {});
      setProviders(response.ok ? statusItems(response.value) : []);
    } catch {
      setProviders([]);
      setProviderError("CLI status is unavailable.");
    } finally {
      setProviderBusy(false);
    }
  };
  const signIn = async (provider) => {
    setProviderBusy(true);
    setProviderError("");
    try {
      const response = await rpc.call("/api", "openduck-cli/login", { provider });
      if (!response.ok)
        setProviderError("Terminal sign-in could not start.");
    } catch {
      setProviderError("Terminal sign-in could not start.");
    } finally {
      setProviderBusy(false);
    }
  };
  import_react.useEffect(() => {
    refreshProviders();
  }, [rpc]);
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
  return /* @__PURE__ */ import_react.default.createElement("section", null, /* @__PURE__ */ import_react.default.createElement("h2", null, "CLI subscriptions"), /* @__PURE__ */ import_react.default.createElement("p", null, "Installed Codex, Claude and Kimi CLIs are detected automatically; no connection step is needed for chat. Pick one of their models in a new chat. Optional delegation and Computer MCP overlays still use ", /* @__PURE__ */ import_react.default.createElement("code", null, "make connect-codex"), ", ", /* @__PURE__ */ import_react.default.createElement("code", null, "make connect-claude"), ", ", /* @__PURE__ */ import_react.default.createElement("code", null, "make connect-kimi"), " and ", /* @__PURE__ */ import_react.default.createElement("code", null, "make connect-computer"), "."), /* @__PURE__ */ import_react.default.createElement("h2", null, "CLI root chat"), /* @__PURE__ */ import_react.default.createElement("p", null, "Installed Codex, Claude, and Kimi CLIs appear with their configured default model. Select a CLI model in a blank session and OpenDuck switches it to the CLI root preset. Each turn uses that session’s selected workspace. Root chat is text-only: host-tool schemas are never sent to a subscription CLI and DSH tools cannot run in this mode."), /* @__PURE__ */ import_react.default.createElement("label", null, /* @__PURE__ */ import_react.default.createElement("input", {
    type: "checkbox",
    checked: cliDraft.enabled,
    disabled: !writable || pending,
    onChange: (event) => setCli({ ...cliDraft, enabled: event.target.checked })
  }), " Enable CLI root chat"), /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Button, {
    disabled: !writable || pending || !cliDirty,
    onClick: () => {
      saveCli();
    }
  }, "Save CLI root chat"), /* @__PURE__ */ import_react.default.createElement("p", null, "Changes to this switch take effect when DSH restarts."), /* @__PURE__ */ import_react.default.createElement("div", {
    style: { display: "grid", gap: 6, marginTop: 10 }
  }, /* @__PURE__ */ import_react.default.createElement("strong", null, "CLI sign-in"), /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Button, {
    disabled: providerBusy,
    onClick: () => {
      refreshProviders();
    }
  }, "Refresh CLI status"), providers.length === 0 && !providerBusy && /* @__PURE__ */ import_react.default.createElement("p", {
    role: "status"
  }, "No installed CLI status is available yet."), providers.map((provider) => /* @__PURE__ */ import_react.default.createElement("div", {
    key: provider.provider
  }, provider.label, ": ", !provider.installed ? "not installed" : provider.auth === "authenticated" ? "signed in" : provider.auth === "not-signed-in" ? "sign-in required" : "status unavailable", " ", provider.installed && provider.auth !== "authenticated" && /* @__PURE__ */ import_react.default.createElement(import_dsh_client_ui_primitives.Button, {
    disabled: providerBusy,
    onClick: () => {
      signIn(provider.provider);
    }
  }, provider.auth === "unknown" ? "Sign in" : "Open sign-in"))), providerError && /* @__PURE__ */ import_react.default.createElement("p", {
    role: "alert"
  }, providerError)), /* @__PURE__ */ import_react.default.createElement("h2", null, "External history projects"), /* @__PURE__ */ import_react.default.createElement("p", null, "Only exact existing project directories listed here can be queried by the read-only history viewer."), snapshot.status && snapshot.status !== "ready" && /* @__PURE__ */ import_react.default.createElement("p", {
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
      const result = await rpc.call("/api", "openduck-history/projects", {});
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
      const result = await rpc.call("/api", "openduck-history/sessions", { projectId, provider, limit: 25, ...cursor ? { cursor } : {} });
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
      const result = await rpc.call("/api", "openduck-history/messages", { projectId, provider, sessionId, limit: 100, ...cursor ? { cursor } : {} });
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

// src/client/CliRootAuthAction.tsx
var import_react4 = __toESM(require("react"), 1);
var import_dsh_client_ui_primitives4 = require("@deepseek-ai/dsh-client-ui-primitives");
var routeProvider = { "codex-cli": "codex", "claude-cli": "claude", "kimi-acp": "kimi" };
var labels = { codex: "Codex", claude: "Claude", kimi: "Kimi" };
function authFor(value, provider) {
  if (value === null || typeof value !== "object" || !Array.isArray(value.items))
    return;
  const item = value.items.find((entry) => entry !== null && typeof entry === "object" && entry.provider === provider);
  const auth = item !== null && typeof item === "object" ? item.auth : undefined;
  return auth === "authenticated" || auth === "not-signed-in" || auth === "unknown" ? auth : undefined;
}
var observedProvider = new Map;
var CliRootAuthAction = ({ sessionId, modelDirectories, sessions, presets, rpc }) => {
  const [notice, setNotice] = import_react4.useState();
  const launched = import_react4.useRef(new Set);
  const selectionEpoch = import_react4.useRef(0);
  import_react4.useEffect(() => {
    let directory;
    try {
      directory = modelDirectories.directoryFor(sessionId);
    } catch {
      return;
    }
    let alive = true;
    const selectRootPreset = async (epoch, quiet = false) => {
      if (!alive || epoch !== selectionEpoch.current)
        return false;
      const refuse = () => {
        if (alive && !quiet)
          setNotice({ kind: "new-session" });
        return false;
      };
      const session = sessions.list.getSnapshot().byId[sessionId];
      if (session === undefined || !session.blank)
        return refuse();
      if (session.projectionValues?.agentPreset === "openduck-cli-root")
        return true;
      try {
        const response = await presets.agentPresets.select(sessionId, "openduck-cli-root");
        if (!alive || epoch !== selectionEpoch.current)
          return false;
        return response.ok ? true : refuse();
      } catch {
        return refuse();
      }
    };
    const inspect = () => {
      const state = directory.store.getSnapshot();
      if (state.status !== "ready")
        return;
      const current = state.current?.provider ?? null;
      const hadBaseline = observedProvider.has(sessionId);
      const previous = observedProvider.get(sessionId);
      observedProvider.set(sessionId, current);
      const changed = hadBaseline && previous !== current;
      const provider = routeProvider[current ?? ""];
      if (provider === undefined)
        return;
      if (!changed) {
        const session = sessions.list.getSnapshot().byId[sessionId];
        if (session?.blank === true && session.projectionValues?.agentPreset !== "openduck-cli-root")
          selectRootPreset(++selectionEpoch.current, true);
        return;
      }
      const epoch = ++selectionEpoch.current;
      (async () => {
        if (!await selectRootPreset(epoch) || !alive || epoch !== selectionEpoch.current)
          return;
        try {
          const response = await rpc.call("/api", "openduck-cli/status", {});
          const auth = response.ok ? authFor(response.value, provider) : undefined;
          if (!alive || epoch !== selectionEpoch.current || auth === undefined || auth === "authenticated")
            return;
          if (auth === "not-signed-in" && !launched.current.has(provider)) {
            launched.current.add(provider);
            const login = await rpc.call("/api", "openduck-cli/login", { provider });
            if (!alive || epoch !== selectionEpoch.current)
              return;
            if (!login.ok) {
              setNotice({ kind: "auth", provider, auth, launched: false, failed: true });
              return;
            }
            setNotice({ kind: "auth", provider, auth, launched: true });
            return;
          }
          setNotice({ kind: "auth", provider, auth, launched: false });
        } catch {
          if (alive && epoch === selectionEpoch.current)
            setNotice({ kind: "auth", provider, auth: "unknown", launched: false, failed: true });
        }
      })();
    };
    const stop = directory.store.subscribe(inspect);
    inspect();
    return () => {
      alive = false;
      stop();
    };
  }, [modelDirectories, presets, rpc, sessionId, sessions]);
  if (notice === undefined)
    return null;
  if (notice.kind === "new-session")
    return /* @__PURE__ */ import_react4.default.createElement("span", {
      role: "status"
    }, "Start a new OpenDuck CLI root chat to use this CLI model.");
  if (notice.launched)
    return /* @__PURE__ */ import_react4.default.createElement("span", {
      role: "status"
    }, "Finish ", labels[notice.provider], " sign-in in Terminal.");
  return /* @__PURE__ */ import_react4.default.createElement("span", null, notice.failed && /* @__PURE__ */ import_react4.default.createElement("span", {
    role: "alert"
  }, "Terminal sign-in could not start. "), /* @__PURE__ */ import_react4.default.createElement(import_dsh_client_ui_primitives4.Button, {
    onClick: () => {
      rpc.call("/api", "openduck-cli/login", { provider: notice.provider }).then((result) => {
        setNotice({ ...notice, launched: result.ok, failed: !result.ok });
      }).catch(() => {
        setNotice({ ...notice, launched: false, failed: true });
      });
    }
  }, notice.auth === "unknown" ? `Sign in to ${labels[notice.provider]}` : `Open ${labels[notice.provider]} sign-in`));
};

// src/client/index.tsx
var inject = ["slots", "connection", "configForms", "remote", "remote.agentPresets", "modelDirectories", "sessions"];
var apply = (ctx) => {
  const form = ctx.configForms.get("openduck");
  ctx.effect(() => ctx.configForms.whileServed(["openduck"], () => ctx.slots.inject("plugins.item", () => ctx.slots.register({
    name: "plugins.item",
    id: "openduck",
    order: 30,
    label: () => "OpenDuck",
    inject: () => ({})
  }, ({ view }) => view === "summary" ? "CLI subscriptions, root chat and external history." : /* @__PURE__ */ import_react5.default.createElement(OpenDuckSettingsCard, {
    scope: form,
    rpc: ctx.connection.rpc
  })))), "openduck-base.settings-page");
  ctx.slots.inject("sidebar.footer.action", () => ctx.slots.register({
    name: "sidebar.footer.action",
    id: "openduck-cli-history",
    locale: "settings.plugins",
    inject: () => ({})
  }, ({ wide }) => /* @__PURE__ */ import_react5.default.createElement(HistorySidebarAction, {
    rpc: ctx.connection.rpc,
    wide: wide === true
  })));
  ctx.slots.inject("conversation.input.dock", () => ctx.slots.register({
    name: "conversation.input.dock",
    id: "openduck-cli-auth",
    order: 30,
    inject: (sessionId) => ({ dockSessionId: sessionId })
  }, ({ dockSessionId }) => dockSessionId === undefined ? null : /* @__PURE__ */ import_react5.default.createElement(CliRootAuthAction, {
    sessionId: dockSessionId,
    modelDirectories: ctx.modelDirectories,
    sessions: ctx.sessions,
    presets: ctx.remote,
    rpc: ctx.connection.rpc
  })));
};
var NativeButton = import_dsh_client_ui_primitives5.Button;

    return module.exports;
  },
})
