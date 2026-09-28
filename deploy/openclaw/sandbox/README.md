# OpenClaw sandbox image

This Dockerfile is the repository-local copy of the official inline default
sandbox image definition from the installed OpenClaw documentation:
`node_modules/openclaw/docs/gateway/sandboxing.md` (Build the default image).

Build it locally with:

```sh
docker build -t openclaw-sandbox:bookworm-slim -f deploy/openclaw/sandbox/Dockerfile .
```

The image intentionally contains no Node runtime and runs as the unprivileged
`sandbox` user in `/home/sandbox`.
