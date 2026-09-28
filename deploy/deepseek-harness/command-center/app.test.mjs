import test from "node:test";
import assert from "node:assert/strict";
import { approvalRetryHeaders, clearApproval, serializeChatOrder, showApproval, state, submitComposer, validApprovalRequired, validAssistantResult } from "./app.js";

const base = { schema_version: "assistant-turn-result.v1", chat_id: "run_123", state: "running", started_at: "2026-08-20T00:00:00Z" };
test("chat UI accepts only bounded async run states", () => {
  assert.equal(validAssistantResult(base), true);
  assert.equal(validAssistantResult({ ...base, state: "completed", answer: "OK", completed_at: "2026-08-20T00:00:01Z" }), true);
  assert.equal(validAssistantResult({ ...base, state: "completed", answer: "OK", error_code: "X" }), false);
  assert.equal(validAssistantResult({ ...base, thread_id: "x", extra: true }), false);
});

test("owner approval retry retains the exact serialized order and is manual", () => {
  const body = serializeChatOrder("chat_fixed", "same bytes");
  assert.deepEqual(JSON.parse(body), { schema_version: "general-chat-order.v1", chat_id: "chat_fixed", prompt: "same bytes", workspace_roots: [], classification: "L0", max_output_bytes: 262144, approval_policy: "never", read_only: true, tools_disabled: true, network_mode: "model_only" });
  assert.equal(body, serializeChatOrder("chat_fixed", "same bytes"));
  assert.deepEqual(approvalRetryHeaders("0123456789abcdef0123456789abcdef"), { "X-Owner-Approval-Request-ID": "0123456789abcdef0123456789abcdef" });
  assert.equal(validApprovalRequired({ schema_version: "owner-approval-required.v1", error_code: "OWNER_APPROVAL_REQUIRED", request_id: "0123456789abcdef0123456789abcdef", order_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", expires_at: "2099-01-01T00:00:00Z" }), true);
});

test("pending approval locks the composer so a second tab submit cannot replace retained bytes", async () => {
  const originalDocument = globalThis.document;
  const elements = {
    "composer": { value: "different second-tab text", disabled: false },
    "composer-submit": { disabled: false },
    "owner-approval-retry": { hidden: false, disabled: false },
    "chat-result": { hidden: true, className: "", textContent: "" },
  };
  globalThis.document = { getElementById: (id) => elements[id] };
  state.controller = "ready";
  state.synthetic = false;
  state.approval = { body: serializeChatOrder("chat_original", "original retained bytes"), requestId: "0123456789abcdef0123456789abcdef", expiresAt: Date.now() + 60_000 };
  let prevented = false;
  await submitComposer({ preventDefault: () => { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(elements.composer.disabled, true);
  assert.equal(elements["composer-submit"].disabled, true);
  assert.equal(state.approval.body, serializeChatOrder("chat_original", "original retained bytes"));
  showApproval({ expires_at: "2099-01-01T00:00:00Z" });
  assert.match(elements["chat-result"].textContent, /sudo '\/Library\/Application Support\/OpenDuck\/operator\/openduck-owner-grant'/);
  clearApproval();
  globalThis.document = originalDocument;
});
