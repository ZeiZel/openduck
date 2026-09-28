package codexruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestReadAssistantCompletedToleratesProgressAndBindsExactlyOneMessage(t *testing.T) {
	s := &scripted{responses: []string{response(1, `{}`), response(2, `{"thread":{"id":"th"}}`), response(3, `{"turn":{"id":"tu"}}`), `{"method":"item/started","params":{}}
{"method":"item/completed","params":{"item":{"type":"agentMessage","text":"hello"}}}
{"method":"turn/completed","params":{"threadId":"th","turn":{"id":"tu","status":"completed"}}}
`}}
	c := NewClient(s)
	if err := c.Initialize(context.Background(), InitializeParams{}); err != nil {
		t.Fatal(err)
	}
	thread, err := c.StartThread(context.Background(), ThreadParams{})
	if err != nil || thread != "th" {
		t.Fatal(err)
	}
	if err := c.StartTurn(context.Background(), TurnParams{ThreadID: thread, Prompt: "x"}); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadAssistantCompleted(context.Background(), 10)
	if err != nil || got.Answer != "hello" || got.TurnID != "tu" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestReadAssistantCompletedRejectsToolAndDuplicateMessages(t *testing.T) {
	for _, events := range []string{
		`{"method":"item/toolCall","params":{}}
`,
		`{"method":"item/completed","params":{"item":{"type":"agentMessage","text":"one"}}}
{"method":"item/completed","params":{"item":{"type":"agentMessage","text":"two"}}}
`,
	} {
		s := &scripted{responses: []string{events}}
		c := NewClient(s)
		c.threadStarted, c.turnStarted, c.threadID, c.turnID = true, true, "th", "tu"
		if _, err := c.ReadAssistantCompleted(context.Background(), 100); err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("events=%q err=%v", events, err)
		}
	}
}

func TestLoginCompletionIsCorrelatedServerNotification(t *testing.T) {
	for _, event := range []string{
		`{"method":"account/login/completed","params":{"success":true,"loginId":"login-1"}}` + "\n",
		`{"method":"account/login/completed","params":{"success":false,"loginId":"login-1","error":"denied"}}` + "\n",
		`{"method":"account/login/completed","params":{"success":true,"loginId":"other"}}` + "\n",
	} {
		c := NewClient(&scripted{responses: []string{event}})
		err := c.WaitLoginCompleted(context.Background(), "login-1")
		if strings.Contains(event, `"success":true,"loginId":"login-1"`) && err != nil {
			t.Fatalf("success err=%v", err)
		}
		if !strings.Contains(event, `"success":true,"loginId":"login-1"`) && err == nil {
			t.Fatalf("bad event accepted")
		}
	}
}
