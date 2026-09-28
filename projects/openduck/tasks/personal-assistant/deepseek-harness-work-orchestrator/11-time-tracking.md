# 11. Планирование и учёт времени

## Semantics

Система различает:

- `planned` — estimate/capacity allocation;
- `explicit` — owner start/pause/resume/stop/adjust;
- `derived_candidate` — предположение из foreground task/terminal/IDE activity;
- `provider` — импорт Kaiten/другого approved source;
- `exported` — receipt внешнего time-log effect.

Derived candidate никогда автоматически не становится confirmed time и не используется как юридический/HR timesheet.

## Timer rules

- timer связан с owner и одним WorkItem; параллельные timers требуют явного режима;
- monotonic clock определяет duration, wall clock — отображение;
- sleep/wake, timezone/DST и restart создают reconciliation prompt, если interval неоднозначен;
- idle detection только после DR-009, с локальной обработкой и без capture content;
- adjustment создаёт superseding event/reason, история не переписывается;
- private activity details не выводятся в general UI/audit.

## Planning views

Command Center показывает planned vs spent vs remaining, estimate range, daily capacity, context-switch count, review/meeting overhead, overtime candidate и forecast impact. Отображение overtime — estimate, не legal record.

## Kaiten reconciliation

TaskLink сопоставляет local TimeEntry с Kaiten card. Provider time logs читаются отдельно, duplicate/overlap/conflict видимы. Export preview показывает task/card, start/end/duration, comment/description and timezone. Writer не может менять card status или другие fields тем же grant.

## Privacy

Baseline не читает keystrokes, clipboard, screen contents, browser history или названия всех окон для timesheet. Допустимые activity signals и retention утверждаются DR-009. Минимальный безопасный режим — только owner commands и dispatch lifecycle.

## Reports

Daily/weekly report формируется из confirmed entries и помечает estimates/candidates. Owner выбирает accept/edit/exclude. Tech-base write и provider export — разные approvals/effects.
