import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

const PD = "ollama/qwen3:8b";
const MARKER = /^\uFEFF?[ \t]*Это ПД[ \t]*(?:\r?\n|$)/;
const TOKEN = /^P-[A-Z0-9]{32}$/;
const CONFUSABLE = /(?:это|е[тt]о)\s*[ППППPР]\s*[ДДDВB]|э\s*т\s*о\s*[ППP]\s*[ДD]/iu;

export function hasCanonicalPdMarker(input) {
  return typeof input === "string" && MARKER.test(input);
}
export function hasPdNearMiss(input) {
  if (typeof input !== "string" || hasCanonicalPdMarker(input)) return false;
  return CONFUSABLE.test(input) || /(^|[\s\p{P}])(?:это\s*[\p{P}]*\s*п\s*[\p{P}]*\s*д|eto\s*[\p{P}]*\s*pd)(?=$|[\s\p{P}])/iu.test(input);
}

export function validateSafeEnvelope(value) {
  if (!value || value.schema_version !== "1.0" || !["draft_reply", "summarize", "extract_candidates"].includes(value.purpose)) return false;
  if (Object.keys(value).some((k) => !["schema_version", "purpose", "session_ref", "messages", "constraints", "egress_attestation"].includes(k))) return false;
  if (typeof value.session_ref !== "string" || !/^psn_[A-Za-z0-9_-]+$/.test(value.session_ref)) return false;
  if (!Array.isArray(value.messages) || value.messages.length > 20) return false;
  if (!value.messages.every((m) => m && TOKEN.test(m.speaker) && typeof m.text === "string" && m.text.length <= 4000 && !/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e]/u.test(m.text))) return false;
  const a = value.egress_attestation;
  if (value.messages.some((m) => /https?:\/\//i.test(m.text))) return false;
  return a && a.policy_version && (a.max_class === "L0" || a.max_class === "L1") && a.decision === "allow" && /^sha256:[0-9a-f]{64}$/.test(a.digest);
}

export class PDPolicy {
  constructor({ statePath, audit = () => {} } = {}) {
    this.statePath = statePath;
    this.audit = audit;
    this.sessions = new Map();
    this.corrupt = false;
    this.load();
  }
  load() {
    if (!this.statePath) return;
    try {
      if (!fs.existsSync(this.statePath)) return;
      const x = JSON.parse(fs.readFileSync(this.statePath, "utf8"));
      if (!x || typeof x.sessions !== "object") throw new Error("invalid state");
      for (const [k, v] of Object.entries(x.sessions)) if (v !== "pd" && v !== "quarantine") throw new Error("invalid latch"); else this.sessions.set(k, v);
    } catch { this.corrupt = true; }
  }
  persist() {
    if (!this.statePath) return;
    const dir = path.dirname(this.statePath); fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${this.statePath}.tmp-${process.pid}-${randomUUID()}`;
    const fdw = fs.openSync(tmp, "wx", 0o600); fs.writeFileSync(fdw, JSON.stringify({ version: 1, sessions: Object.fromEntries(this.sessions) }) + "\n"); fs.fsyncSync(fdw); fs.closeSync(fdw);
    fs.renameSync(tmp, this.statePath); const dirfd = fs.openSync(dir, "r"); try { fs.fsyncSync(dirfd); } finally { fs.closeSync(dirfd); }
  }
  mode(sessionKey, prompt = "") {
    if (this.corrupt || typeof sessionKey !== "string" || sessionKey.length === 0 || sessionKey.length > 512) return "deny";
    const old = this.sessions.get(sessionKey);
    if (old === "pd") return "pd";
    if (old === "quarantine") return "quarantine";
    if (hasCanonicalPdMarker(prompt)) {
      try { this.sessions.set(sessionKey, "pd"); this.persist(); } catch { this.corrupt = true; return "deny"; }
      this.audit({ event: "mode_latched", mode: "pd" }); return "pd";
    }
    if (hasPdNearMiss(prompt)) {
      try { this.sessions.set(sessionKey, "quarantine"); this.persist(); } catch { this.corrupt = true; return "deny"; }
      this.audit({ event: "mode_latched", mode: "quarantine" }); return "quarantine";
    }
    return "normal";
  }
  beforeModelResolve(event = {}) {
    const mode = this.mode(event.sessionKey, event.prompt ?? "");
    if (mode === "pd" || mode === "quarantine") return { providerOverride: "ollama", modelOverride: "qwen3:8b" };
    if (mode === "deny") return { providerOverride: "__deny__", modelOverride: "__deny__" };
    return {};
  }
  beforeAgentRun(event = {}) {
    const mode = this.mode(event.sessionKey, event.prompt ?? "");
    if (mode === "deny") return { outcome: "block", reason: "policy_state_invalid", message: "Локальная политика недоступна; запуск запрещён." };
    const provider = event.provider ?? event.modelProviderId;
    const model = event.model ?? event.modelId;
    if ((mode === "pd" || mode === "quarantine") && ((provider && provider !== "ollama") || (model && model !== "qwen3:8b" && model !== PD))) return { outcome: "block", reason: "pd_model_mismatch", message: "ПД-сообщения обрабатываются только локальной моделью." };
    return { outcome: "pass" };
  }
  beforeToolCall(event = {}) {
    const mode = this.mode(event.sessionKey, "");
    if (mode === "pd" || mode === "quarantine") return { block: true, blockReason: "локальный карантин запрещает инструменты" };
    if (event.toolName !== "codex_delegate") return {};
    if (!validateSafeEnvelope(event.params?.envelope)) return { block: true, blockReason: "недействительный safe-envelope" };
    return {};
  }
}

export function definePluginEntry() {
  return {
    id: "openduck-pd-router", name: "OpenDuck PD Router",
    register(api) {
      const cfg = api.pluginConfig ?? {};
      const policy = new PDPolicy({ statePath: cfg.statePath ?? ".openduck/pd-router-state.json", audit: (x) => api.log?.({ event: x.event, mode: x.mode }) });
      const sessionKey = (ctx) => ctx?.sessionKey ?? ctx?.sessionId;
      api.on("before_model_resolve", (e, ctx) => policy.beforeModelResolve({ ...e, sessionKey: sessionKey(ctx) }), { priority: 1000 });
      api.on("before_agent_run", (e, ctx) => policy.beforeAgentRun({ ...e, sessionKey: sessionKey(ctx), modelProviderId: ctx?.modelProviderId, modelId: ctx?.modelId }), { priority: 1000 });
      api.on("before_tool_call", (e, ctx) => policy.beforeToolCall({ ...e, sessionKey: ctx?.sessionKey ?? ctx?.sessionId }), { priority: 1000 });
      api.registerTrustedToolPolicy?.({ id: "pd-router", description: "Fail-closed local PD tool gate", evaluate: (e, ctx) => policy.beforeToolCall({ ...e, sessionKey: ctx?.sessionKey ?? ctx?.sessionId }) });
    },
  };
}

export default definePluginEntry();
