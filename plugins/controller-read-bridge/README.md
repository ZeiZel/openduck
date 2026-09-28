# Controller Read Bridge

This package is a disabled-by-default, browser-only client for the three
bounded OpenDuck Controller plugin-read projections. It bootstraps an
ephemeral UI channel and keeps the bearer token and nonces only in a closure.
It never writes browser storage, creates a model/session, logs payloads, or
uses `postMessage`.

The endpoint is pinned to literal loopback `http://127.0.0.1:8788`; redirects,
queries, non-JSON responses, oversized bodies, and expired/unauthorized
sessions fail closed.
