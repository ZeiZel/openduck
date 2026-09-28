# 08. Outlook Mail и Calendar

## Capability status

`USER REQUIREMENT`: отслеживать изменения Outlook.

`VERIFIED / session inventory`: Outlook Email и Outlook Calendar присутствуют только в рекомендованном каталоге Codex/ChatGPT и **не установлены**. Это не runtime capability DSH и не dependency baseline.

`PROPOSAL`: собственный `openduck-graph-reader` sidecar на Microsoft Graph с delegated owner session и минимальными scopes. Writer credentials/effectors проектируются отдельно и остаются disabled.

## Permissions baseline

`VERIFIED / Microsoft Graph permissions reference`:

- `Mail.ReadBasic` читает basic properties, исключая body/bodyPreview, attachments и extended properties;
- `Calendars.ReadBasic` по permissions reference и `calendarView` page читает basic event details без body/attachments/extensions;
- расширение до `Mail.Read`/`Calendars.Read` либо shared/application scopes требует отдельного DR-005, tenant/admin evidence и privacy review;
- `Mail.Send`, `Mail.ReadWrite`, `Calendars.ReadWrite` не входят в reader consent.

OAuth refresh/access tokens остаются в OS-backed credential broker; DSH, model, repo, logs и Beads получают только credential reference/status, не значение. До real Graph login/reader DR-020 требует isolated principal/app container, Keychain ACL and mailbox-cache read-deny against malicious DSH; process/ref alone insufficient.

## Mail change tracking

Reader выполняет bounded initial sync выбранных folders и далее message delta per folder. Opaque `@odata.nextLink`/`@odata.deltaLink` хранятся encrypted и используются целиком; client не парсит/редактирует token. Обрабатываются create/update/delete/move и read/unread changes с folder-level semantics.

Basic triage fields: message/conversation ID, sender/from, recipients count or policy-approved refs, subject, received/sent time, importance, flags, hasAttachments. Body/preview/attachments отсутствуют; request расширения создаёт scope decision, а не silent fetch.

## Calendar permission conflict и tracking

`CONFLICT / 2026-08-19`: официальные Microsoft pages/version surfaces расходятся либо меняются по least-privileged permission для event/calendar delta (`Calendars.ReadBasic` vs `Calendars.Read`). Поэтому calendar delta baseline **off**. Разрешён только bounded `calendarView` polling с `Calendars.ReadBasic`, если pinned v1.0 live probe на целевом tenant/account докажет expected fields/recurrence/paging. Если требуемый delta route возвращает permission failure или official pinned page требует `Calendars.Read`, Controller не расширяет scope: нужен отдельный DR-005 owner/security decision и новый consent.

После решения reader либо bounded-poll’ит утверждённое window, либо отслеживает delta отдельно по calendar. Хранятся event ID, iCalUID/series links, basic start/end/timezone/status/location/organizer fields, recurrence identifiers and cursor. Window change требует new full sync/coverage record. Unsupported delete/recurrence semantics остаются gap, не reconstructed fact.

## Triage and planning

- Mail change создаёт local candidate: urgency, related task/peer, reply/action/memory candidate.
- Calendar change обновляет projection и создаёт conflict/PlanDelta.
- Subject/attendee matching не создаёт TaskLink автоматически при ambiguity.
- Mail content рассматривается как untrusted и проходит тот же PD/injection gate.

## Writer effectors

Будущие `mail-send/reply`, `mail-move/flag`, `calendar-create/update/delete/respond` получают отдельные app registrations/scopes/processes либо строго раздельные credential references. Каждый action показывает mailbox/calendar/event/recipient/body/time exact preview и current provider revision. Reader binary не содержит mutation routes.

## Recovery

401/consent expiry, 403/admin policy, 410/invalid delta, throttling, paging interruption и timezone/recurrence ambiguity отражаются как degraded/gap. Full resync не удаляет local evidence до reconciliation. Реальные mailbox/calendar не подключаются до DR-005, DR-007, DR-011, retention и synthetic Graph fixture tests; permission failure никогда не вызывает automatic `Calendars.Read` escalation.
