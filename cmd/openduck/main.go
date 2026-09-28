package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"flag"
	"log"
	"net"
	"net/http"
	"openduck/internal/core"
	"openduck/internal/server"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:8787", "loopback listen address")
	queuePath := flag.String("queue", ".openduck/queue.enc", "encrypted local queue path")
	pseudonymPath := flag.String("pseudonyms", ".openduck/pseudonyms.enc", "encrypted local pseudonym mapping path")
	flag.Parse()
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal(err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		log.Fatal("listen address must be explicit loopback IP")
	}
	if err := os.MkdirAll(filepath.Dir(*queuePath), 0700); err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	queueKey, err := (core.MacOSKeychainProvider{Service: "openduck", Account: "queue"}).Key(ctx)
	if err != nil {
		log.Fatal("queue key unavailable")
	}
	q, err := core.NewFileQueue(*queuePath, queueKey)
	if err != nil {
		log.Fatal("queue unavailable")
	}
	h := hmac.New(sha256.New, queueKey)
	_, _ = h.Write([]byte("openduck/pseudonym-store/v1"))
	pseudoKey := h.Sum(nil)
	for i := range queueKey {
		queueKey[i] = 0
	}
	store, err := core.NewPersistentPseudonymStore(ctx, *pseudonymPath, pseudoKey)
	for i := range pseudoKey {
		pseudoKey[i] = 0
	}
	if err != nil {
		log.Fatal("pseudonym store unavailable")
	}
	// Keep the durable mapper in the composition root even while cloud egress is disabled.
	mapper, err := core.NewDurablePseudonymizer(h.Sum(nil), store)
	if err != nil {
		log.Fatal("pseudonymizer unavailable")
	}
	srv := &http.Server{Addr: *addr, Handler: (&server.Server{Queue: q, Pseudonymizer: mapper, Mode: "manual-copy/local-only"}).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
