package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"openduck/internal/beadsview"
	"openduck/internal/dshbridge"
	"openduck/internal/dshbridgehttp"
	"openduck/internal/workspacegroup"
)

type beadsFixture struct{}
func (beadsFixture) Scopes(context.Context) ([]beadsview.Scope,error) { return nil,nil }
func (beadsFixture) Graph(context.Context, beadsview.Namespace) (beadsview.Graph,error) { return beadsview.Graph{Nodes:[]beadsview.GraphNode{{ID:"n1",Title:"First",Status:"open"},{ID:"n2",Title:"Second",Status:"closed"}},Edges:[]beadsview.GraphEdge{{From:"n1",To:"n2"}}},nil }
func (beadsFixture) Search(context.Context, beadsview.Namespace,string) ([]beadsview.SearchResult,error) { return nil,nil }
func (beadsFixture) MemoryChats(context.Context, beadsview.Namespace) ([]beadsview.MemoryChatMetadata,error) { panic("global provider must never be called") }
type workspaceFixture struct{}
func (workspaceFixture) ListProjections(context.Context) ([]workspacegroup.SafeProjection,error) { return []workspacegroup.SafeProjection{},nil }

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:0"); if err != nil { fmt.Fprintln(os.Stderr, "listen failed"); os.Exit(2) }
	host := listener.Addr().String(); origin := "http://" + host
	store, err := dshbridge.NewSessionStore(dshbridge.Config{Origin:origin, Host:host}); if err != nil { fmt.Fprintln(os.Stderr, "session failed"); os.Exit(2) }
	bridge := &dshbridge.Bridge{Sessions:store}
	handler := (&dshbridgehttp.Server{Bridge:bridge, Origin:origin, Host:host, PluginReads:dshbridge.SafePluginReads{Beads:beadsFixture{}, Workspace:workspaceFixture{}}}).Handler()
	server := &http.Server{Handler:handler, ReadHeaderTimeout:2*time.Second}
	go func(){ _ = server.Serve(listener) }()
	fmt.Printf("READY %s\n", host); _ = os.Stdout.Sync()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT); defer stop(); <-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), time.Second); defer cancel(); _ = server.Shutdown(shutdown)
}
