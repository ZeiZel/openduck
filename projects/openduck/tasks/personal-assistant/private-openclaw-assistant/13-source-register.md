# 13. Реестр источников

Все источники ниже — первичные/официальные, проверены `verified_at: 2026-08-12`. Реестр подтверждает только заявленное в колонке «Использование». Возможность конкретного аккаунта, версии, канала, scope или модели требует live capability probe при реализации.

## OpenClaw

| ID | URL | verified_at | Использование |
|---|---|---|---|
| SRC-OC-01 | https://docs.openclaw.ai/ | 2026-08-12 | официальный home/overview; отправная точка, не evidence конкретной интеграции |
| SRC-OC-02 | https://docs.openclaw.ai/channels | 2026-08-12 | официальный каталог/обзор channel capabilities; конкретный adapter проверяется отдельно |
| SRC-OC-03 | https://docs.openclaw.ai/gateway/security | 2026-08-12 | personal-assistant trust model, gateway exposure, allowlists, permissions, plugin/tool risks, security audit |
| SRC-OC-04 | https://docs.openclaw.ai/concepts/session | 2026-08-12 | session state/storage/maintenance; session routing не принимается за authorization |
| SRC-OC-05 | https://docs.openclaw.ai/concepts/main-session | 2026-08-12 | isolation scopes и risk cross-conversation context |
| SRC-OC-06 | https://docs.openclaw.ai/providers/ollama | 2026-08-12 | local Ollama provider/discovery и отличие локальных/cloud routes |
| SRC-OC-07 | https://docs.openclaw.ai/plugins/hooks | 2026-08-12 | typed plugin hooks; hooks не заменяют внешнюю policy boundary |
| SRC-OC-08 | https://docs.openclaw.ai/automation | 2026-08-12 | background tasks/schedules/hooks/standing instructions; capability не означает разрешение на mutations |
| SRC-OC-09 | https://docs.openclaw.ai/concepts/memory | 2026-08-12 | Markdown memory и local/provider embedding options; memory требует собственной retention/provenance policy |
| SRC-OC-10 | https://docs.openclaw.ai/providers/openai | 2026-08-12 | OpenAI API + Codex auth/routes; route/auth не смешиваются в privacy assumptions |
| SRC-OC-11 | https://docs.openclaw.ai/gateway/security/audit-checks | 2026-08-12 | категории security audit, plugin/skill/tool/config checks |
| SRC-OC-12 | https://docs.openclaw.ai/automation/hooks | 2026-08-12 | managed/bundled hook lifecycle; используется при выборе extension mechanism |
| SRC-OC-13 | https://docs.openclaw.ai/cron | 2026-08-12 | scheduled tasks; mutation/admin semantics проверяются перед применением |

## OpenAI

| ID | URL | verified_at | Использование |
|---|---|---|---|
| SRC-OAI-01 | https://platform.openai.com/docs/models/default-usage-policies-by-endpoint | 2026-08-12 | API data controls: training default, abuse-monitoring retention, application state, endpoint/ZDR eligibility; всегда перепроверять перед enable |
| SRC-OAI-02 | https://help.openai.com/en/articles/7039943-data-controls-faq | 2026-08-12 | consumer vs business service data usage и настройки; причина не приравнивать OAuth к API posture |
| SRC-OAI-03 | https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan | 2026-08-12 | Codex usage через ChatGPT plan и применимость plan data controls; конкретный план владельца — decision evidence |
| SRC-OAI-04 | https://developers.openai.com/codex/ | 2026-08-12 | официальная документация Codex; использовать для runtime/client behavior при реализации |
| SRC-OAI-05 | https://openai.com/enterprise-privacy/ | 2026-08-12 | официальные commitments для business data; применимость определяется типом организации/договора |

## Ollama

| ID | URL | verified_at | Использование |
|---|---|---|---|
| SRC-OLL-01 | https://ollama.com/library/qwen3 | 2026-08-12 | официальный registry с вариантами Qwen3, включая классы размеров для benchmark; не доказательство достаточного качества |
| SRC-OLL-02 | https://docs.ollama.com/api/introduction | 2026-08-12 | официальный local API; loopback/config/endpoint проверяются при реализации |
| SRC-OLL-03 | https://docs.ollama.com/faq | 2026-08-12 | operational behavior и конфигурация; не заменяет network isolation test |

## Verification notes

- `VERIFIED`: OpenClaw docs на дату проверки описывают local Ollama и OpenAI/Codex provider routes, sessions, memory, hooks/automations и security guidance.
- `VERIFIED`: OpenAI API data-control documentation на дату проверки говорит, что API data не используется для training по умолчанию, но описывает abuse-monitoring/application-state retention и eligibility ограничений; точный endpoint/config проверяется снова на Phase 3.
- `VERIFIED`: consumer/business plan controls различаются; поэтому тип подписки и settings являются evidence, а не предположением.
- `VERIFIED`: Ollama registry публикует модели разных размеров. Производительность и безопасность на Mac17,2/M5/24 GB остаются `ASSUMPTION` до локального benchmark.
- `DECISION REQUIRED`: для выбранных Telegram/Slack/Calendar/Call platforms добавить их официальные API/ToS/admin/consent источники в этот реестр до adapter implementation. Пока конкретные платформенные возможности не утверждаются.

## Change protocol

При обновлении источника записать новую дату проверки и краткое изменение в decision/evidence log. Если источник противоречит принятому требованию, создать `CONFLICT`, указать владельца и заблокировать затронутый rollout; не переписывать историю молча.
