# 06. Демо, календарь и планирование

## Demo commitment lifecycle

`USER REQUIREMENT`: фиксировать дату демо по задачам и выводить календарь в Harness.

`PROPOSAL` state machine:

`OBSERVED → CANDIDATE → CLARIFICATION_NEEDED | CONFIRMED → CONFLICTED | SUPERSEDED | CANCELLED`.

Candidate возникает только из явной даты/времени в admitted safe source revision или прямого owner input. Для PD meeting/transcript Qwen-derived demo suggestion остаётся local-only; DSH candidate появляется только из отдельно strict owner-authored exact text после consumed DeclassificationDecision. Относительные выражения («в пятницу», «через неделю») получают resolved interval + original text + timezone assumptions и требуют confirmation. Никакая модель не придумывает missing date.

## Calendar projection

Command Center показывает:

- confirmed demos, Outlook events, milestones и owner blocks;
- timezone исходника и отображение Europe/Moscow;
- task/Kaiten/Beads links;
- source authority, freshness и recurrence;
- overlapping/conflicting candidates без silent merge;
- reminders и preparation windows.

До DR-007 Calendar Ledger — conflict-preserving projection, а не master provider. Outlook write не требуется для отображения.

## WorkGraph

Planner создаёт DAG из `WorkItem` и typed edges: `blocks`, `depends_on`, `part_of`, `must_finish_before_demo`, `resource_conflict`. Узел содержит estimate range, confidence, earliest/latest dates, capacity owner, status, source links и acceptance gate.

Graph views:

- календарь и milestone lane;
- Gantt/timeline;
- dependency/critical-path graph;
- capacity/overload heatmap;
- plan/fact and forecast;
- unscheduled/unlinked/conflicted items.

## Baseline и изменение

Codex может предложить новый graph, но Controller freeze’ит baseline hash. Новое Chat/Kaiten/Outlook/Time событие создаёт `PlanDelta`; UI показывает changed assumptions, downstream milestones, slack/critical path и recommended actions. Baseline меняется отдельным owner decision либо узкой pre-approved scheduling policy, которая не вызывает provider mutation.

## Scheduling policy

- fixed meetings/demo/explicit deadlines имеют hard constraints;
- estimates — ranges, не точные promises;
- context switching и review/contingency capacity учитываются явно;
- uncertain dependencies и missing owner отображаются;
- overdue/stale не «исправляются» изменением даты без provenance;
- plan generates local reminders; external event/task mutation — отдельный effect.

## Reminder lifecycle

Controller scheduler владеет durable reminder jobs. DSH session-local schedule недостаточен. Подписанное native companion приложение запрашивает own-app UserNotifications authorization и планирует `UNNotificationRequest`; delivery best-effort, receipt не равен показу. Notification содержит safe metadata/deep link; PD body не выводится на lock screen.

## Minimum views/queries

- «ближайшие демо и риск»;
- «что нужно закончить до demo X»;
- «что изменилось после последнего baseline»;
- «где план расходится с Kaiten/временем»;
- «какие даты требуют подтверждения».
