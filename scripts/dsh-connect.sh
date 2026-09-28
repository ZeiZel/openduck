#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
dsh_home=${DSH_HOME:-"$root/.dsh-home"}
profile="$dsh_home/profiles/openduck"
usage() { printf 'usage: %s {plugin ABSOLUTE_PATH|codex|claude|kimi|computer|disconnect-codex|disconnect-claude|disconnect-kimi|disconnect-computer|cli-chat|disconnect-cli-chat}\n' "$0" >&2; }
[[ $# -eq 1 || $# -eq 2 ]] || { usage; exit 2; }
kind=$1
case "$kind" in
  plugin)
    [[ $# -eq 2 && -d "$2" ]] || { printf '%s\n' 'plugin requires an existing directory' >&2; exit 2; }
    plugin_path=$(cd "$2" && pwd -P)
    exec "$root/scripts/dsh-base.sh" plugin --profile openduck add "$plugin_path"
    ;;
  codex|claude|kimi)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    command -v "$kind" >/dev/null 2>&1 || { printf 'dsh-connect: %s is not on PATH\n' "$kind" >&2; exit 127; }
    case "$kind" in
      codex) packages=('@deepseek-ai/dsh-subagent-codex@0.1.0-rc.7' '@deepseek-ai/dsh-sdk-protocol@0.1.0-rc.7') ;;
      claude) packages=('@deepseek-ai/dsh-subagent-claude-code@0.1.0-rc.7') ;;
      kimi) packages=('@deepseek-ai/dsh-subagent-acp@0.1.0-rc.7') ;;
    esac
    "$root/scripts/dsh-base.sh" plugin --profile openduck add "${packages[@]}"
    mkdir -p "$profile"
    cp "$root/plugins/openduck-base/connect/$kind.patch.yml" "$profile/openduck-$kind.patch.yml"
    preset="$dsh_home/.agent-presets/openduck-delegation"
    if [[ ! -f "$preset/agent.cordis.yml" ]]; then
      mkdir -p "$preset"
      cp "$root/third_party/deepseek-harness/apps/cli/config/agent-presets/standard/preset.yml" "$preset/preset.yml"
      cp "$root/third_party/deepseek-harness/apps/cli/config/agent-presets/standard/agent.cordis.yml" "$preset/agent.cordis.yml"
      perl -0pi -e 's/^name:.*$/name: OpenDuck · CLI subscriptions/m; s/^description:.*$/description: Connected Codex, Claude Code, and Kimi CLI subscription delegation tools./m' "$preset/preset.yml"
    fi
    tool="tool-subagent-$kind"; [[ "$kind" = claude ]] && tool='tool-subagent-claude-code'; [[ "$kind" = kimi ]] && tool='tool-subagent-kimi'
    if ! perl -0pi -e "s/(    - id: $tool\n      name: '\@deepseek-ai\/dsh-tool-subagent'\n)      disabled: true\n/\$1/" "$preset/agent.cordis.yml"; then :; fi
    if [[ "$kind" = kimi ]] && ! rg -q 'id: tool-subagent-kimi' "$preset/agent.cordis.yml"; then
      perl -0pi -e "s/(\n\s+- id: workflow-worker-thread)/\n    - id: tool-subagent-kimi\n      name: '\@deepseek-ai\/dsh-tool-subagent'\n      config:\n        provider: kimi\n        toolName: subagent_kimi\n        backgroundMode: one-shot\n        maxDepth: provider-managed\n\$1/" "$preset/agent.cordis.yml"
    fi
    printf '%s\n' "Enabled $kind in the openduck profile. make run now loads its host patch; select preset openduck-delegation in native DSH to expose every connected delegation tool."
    ;;
  cli-chat)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    preset="$dsh_home/.agent-presets/openduck-cli-root"
    mkdir -p "$preset"
    if [[ ! -f "$preset/preset.yml" ]]; then
      cp "$root/third_party/deepseek-harness/apps/cli/config/agent-presets/standard/preset.yml" "$preset/preset.yml"
    fi
    # Correct an older generated preset whose title substitution accidentally
    # targeted agent.cordis.yml.
    perl -0pi -e 's/^name:.*$/name: OpenDuck · CLI root chat/m; s/^description:.*$/description: Root chat through configured CLI subscriptions; host tool schemas are disabled./m' "$preset/preset.yml"
    agent="$preset/agent.cordis.yml"
    template="$root/plugins/openduck-base/connect/cli-root-agent.cordis.yml"
    if [[ -f "$agent" ]] && ! cmp -s "$agent" "$template"; then
      # The prior OpenDuck generator copied standard and turned off rows by
      # prefix. It still mounted plan/workflow plugins that add schemas, so it
      # is safe to replace. Refuse an unknown user composition rather than
      # silently enabling a route that could expose a host tool.
      if ! rg -q '^# The `standard` agent preset:' "$agent"; then
        printf '%s\n' 'dsh-connect: openduck-cli-root was customized; its CLI route stays disabled because root chat requires the managed tool-free composition' >&2
        exit 1
      fi
    fi
    cp "$template" "$agent"
    mkdir -p "$profile"
    : > "$profile/openduck-cli-root.enabled"
    printf '%s\n' 'Created the OpenDuck CLI root-chat preset with no DSH host-tool schemas. Configure an explicit canonical workspace and model allowlist in OpenDuck settings, then restart DSH.'
    ;;
  disconnect-cli-chat)
    rm -f "$profile/openduck-cli-root.enabled"
    printf '%s\n' 'Disabled the OpenDuck CLI root-chat route. The generated preset is retained so local preset edits are preserved; restart DSH to apply.'
    ;;
  disconnect-codex|disconnect-claude|disconnect-kimi|disconnect-computer)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    target=${kind#disconnect-}
    rm -f "$profile/openduck-$target.patch.yml"
    preset="$dsh_home/.agent-presets/openduck-delegation/agent.cordis.yml"
    if [[ -f "$preset" ]]; then
      tool="tool-subagent-$target"; [[ "$target" = claude ]] && tool='tool-subagent-claude-code'; [[ "$target" = kimi ]] && tool='tool-subagent-kimi'
      if [[ "$target" = kimi ]]; then
        perl -0pi -e "s/    - id: tool-subagent-kimi\n      name: '\@deepseek-ai\/dsh-tool-subagent'\n(?:      [^\n]*\n)*?(?=    - id:|\z)//" "$preset"
      else
        perl -0pi -e "s/(    - id: $tool\n      name: '\@deepseek-ai\/dsh-tool-subagent'\n)(?!      disabled: true\n)/\$1      disabled: true\n/" "$preset"
      fi
    fi
    printf '%s\n' "Disabled $target in the openduck profile. Restart DSH to apply the profile change."
    ;;
  computer)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    command -v cua-driver >/dev/null 2>&1 || { printf '%s\n' 'dsh-connect: cua-driver is not on PATH' >&2; exit 127; }
    cua-driver permissions status --json >/dev/null
    "$root/scripts/dsh-base.sh" plugin --profile openduck add '@deepseek-ai/dsh-mcp-client@0.1.0-rc.7'
    mkdir -p "$profile"
    cp "$root/plugins/openduck-base/connect/computer.patch.yml" "$profile/openduck-computer.patch.yml"
    printf '%s\n' 'Enabled the explicit Cua Driver MCP bridge in the openduck profile. make run now loads it; no permission was granted and no computer action was sent.'
    ;;
  *) usage; exit 2 ;;
esac
