# ADR 0001: synthetic-only local defaults

Status: accepted for Phases 0–1 (2026-08-12).

The process is foreground-only and binds loopback. Inputs are manual-copy synthetic events;
accounts, outbound network calls, mutations and background daemons are disabled. Deterministic
classification is authoritative; a local model is optional and cannot lower a classification.
Test keys, when needed, are ephemeral and never loaded from Keychain or credentials.
