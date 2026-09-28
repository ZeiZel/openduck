/** @typedef {{id:string,title:string,detail:string,status:string,source:string,coverage:string,privacy:string,kind:string}} CommandCard */
/** @typedef {{schema:string,state:string,generatedAt:string,items:Record<string,CommandCard[]>,metrics:Record<string,number>,health:{controller:string, sources:string[], model:string, effects:string}}} ReadModel */

/** Safe, synthetic-only display fixture. It deliberately contains no raw message or PD body. */
export const SYNTHETIC_READ_MODEL = Object.freeze({
  schema: "openduck.command-center.read-model.v1",
  state: "ready",
  generatedAt: "2026-08-19T16:00:00Z",
  metrics: { inbox: 3, today: 4, openTasks: 8, running: 1, review: 2 },
  health: { controller: "ready", sources: ["Enterprise Chat: complete", "Telegram: best_effort", "Outlook: stale"], model: "external", effects: "disabled" },
  items: {
    inbox: [
      { id: "inbox-001", title: "Запрос по демо-плану", detail: "Нужно подтвердить слот и владельца задачи", status: "candidate", source: "Enterprise Chat", coverage: "complete", privacy: "SAFE", kind: "message" },
      { id: "inbox-002", title: "Изменение карточки Kaiten", detail: "Срок и исполнитель требуют сверки", status: "changed", source: "Kaiten", coverage: "complete", privacy: "SAFE", kind: "task" },
      { id: "inbox-003", title: "Новое письмо требует разбора", detail: "Доступна только разрешённая метаинформация", status: "new", source: "Outlook", coverage: "best_effort", privacy: "UNKNOWN", kind: "mail" }
    ],
    calendar: [{ id: "calendar-001", title: "Демо: Command Center", detail: "Завтра, 15:00–15:45 · Europe/Moscow", status: "confirmed", source: "owner", coverage: "complete", privacy: "SAFE", kind: "demo" }],
    graph: [{ id: "graph-001", title: "UI read-model channel", detail: "4 из 6 зависимостей завершены", status: "running", source: "Controller", coverage: "complete", privacy: "SAFE", kind: "work" }],
    tasks: [{ id: "task-001", title: "Проверить delta Kaiten", detail: "Связь: Kaiten ↔ Beads · следующий checkpoint сегодня", status: "blocked", source: "Kaiten", coverage: "complete", privacy: "SAFE", kind: "work" }],
    time: [{ id: "time-001", title: "Текущий фокус", detail: "01:20 сегодня · прогноз 03:00", status: "running", source: "owner", coverage: "complete", privacy: "SAFE", kind: "timer" }],
    reviews: [{ id: "review-001", title: "Ingress policy review", detail: "2 замечания ожидают решения владельца", status: "review", source: "Controller", coverage: "complete", privacy: "SAFE", kind: "review" }],
    memory: [{ id: "memory-001", title: "Кандидат решения", detail: "Требует подтверждения и provenance", status: "candidate", source: "Beads", coverage: "complete", privacy: "SAFE", kind: "memory" }],
    decisions: [{ id: "decision-001", title: "Права внешнего источника", detail: "Эффекты отключены; требуется явное решение", status: "pending", source: "Controller", coverage: "complete", privacy: "SAFE", kind: "decision" }],
    sessions: [{ id: "session-001", title: "Синтетический сеанс", detail: "Активен · архивирование обратимо", status: "active", source: "Controller", coverage: "complete", privacy: "SAFE", kind: "session" }]
  }
});
