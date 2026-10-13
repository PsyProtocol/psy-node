package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

func (g *gate) data(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Content-Encoding")
	if websocket.IsWebSocketUpgrade(r) {
		g.ws(w, r)
		return
	}
	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return
	}
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	select {
	case g.messageSlots <- struct{}{}:
		defer func() { <-g.messageSlots }()
	default:
		http.Error(w, "RPC buffering capacity busy; request was not forwarded", 503)
		return
	}
	ctx, lease := g.withLease(r.Context())
	defer lease.release()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(30 * time.Second))
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	var reader io.Reader = r.Body
	switch r.Header.Get("Content-Encoding") {
	case "", "identity":
	case "gzip":
		z, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, "invalid gzip", 400)
			return
		}
		defer z.Close()
		reader = z
	default:
		http.Error(w, "unsupported content encoding", 415)
		return
	}
	body, err := bufferedRead(ctx, reader, maxBody)
	if err != nil || len(body) > maxBody {
		http.Error(w, "invalid or oversized body", 413)
		return
	}
	out := g.dispatch(ctx, body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if len(out) == 0 {
		w.WriteHeader(204)
		return
	}
	w.Write(out)
}

func (g *gate) ws(w http.ResponseWriter, r *http.Request) {
	// Realm RPC has request/response methods, not subscription methods. Each WS
	// message follows the same admission path; open connections cannot bypass close.
	select {
	case g.wsSlots <- struct{}{}:
		defer func() { <-g.wsSlots }()
	default:
		http.Error(w, "WebSocket capacity busy", 503)
		return
	}
	u := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	c, err := u.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	c.SetReadLimit(maxBody)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var mu sync.Mutex
	var messages sync.WaitGroup
	defer messages.Wait()
	for {
		// Bound idle sockets; after a frame starts, bound partial-message uploads too.
		c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		_, reader, err := c.NextReader()
		if err != nil {
			cancel()
			return
		}
		g.mu.Lock()
		if g.shuttingDown {
			g.mu.Unlock()
			return
		}
		g.wsMessages++
		g.mu.Unlock()
		finish := func() { g.mu.Lock(); g.wsMessages--; g.mu.Unlock() }
		select {
		case g.messageSlots <- struct{}{}:
		default:
			finish()
			return
		}
		messageCtx, messageLease := g.withLease(ctx)
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		body, err := bufferedRead(messageCtx, reader, maxBody)
		if err != nil {
			finish()
			messageLease.release()
			<-g.messageSlots
			return
		}
		messages.Add(1)
		go func(messageCtx context.Context, lease *lease, body []byte) {
			defer messages.Done()
			defer finish()
			defer func() { <-g.messageSlots }()
			defer lease.release()
			out := g.dispatch(messageCtx, body)
			if len(out) == 0 {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if c.WriteMessage(websocket.TextMessage, out) != nil {
				c.Close()
			}
		}(messageCtx, messageLease, body)
	}
}

func (g *gate) admin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/mode" && r.Method == "PUT" {
		var body struct {
			Mode string `json:"mode"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body) != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if err := g.setMode(body.Mode); err != nil {
			http.Error(w, "mode change failed", 500)
			return
		}
	} else if r.URL.Path != "/status" || r.Method != "GET" {
		http.NotFound(w, r)
		return
	}
	g.mu.Lock()
	mode, active, uncertain := g.mode, g.active, g.persistenceError
	g.mu.Unlock()
	entries, err := os.ReadDir(filepath.Join(g.dir, "ledger"))
	if err != nil {
		http.Error(w, "ledger unreadable", 500)
		return
	}
	pending, completed := 0, 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".done.json") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			pending++
			continue
		}
		data, err := os.ReadFile(filepath.Join(g.dir, "ledger", strings.TrimSuffix(entry.Name(), ".json")+".done.json"))
		var record struct {
			Status string `json:"status"`
		}
		if err != nil || json.Unmarshal(data, &record) != nil || record.Status != "handler_responded_not_proof_of_chain_inclusion" {
			pending++
		} else {
			completed++
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"mode": mode, "active_submissions": active, "pending_or_ambiguous": pending, "responded": completed, "persistence_uncertain": uncertain, "safe_to_stop_processor": false})
}

func main() {
	listen := flag.String("listen", "127.0.0.1:21340", "data listener")
	upstream := flag.String("upstream", "", "private HTTP RPC backend")
	dir := flag.String("state-dir", "", "private persistent state directory")
	admin := flag.String("admin-socket", "", "private Unix control socket")
	flag.Parse()
	u, err := url.Parse(*upstream)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || *dir == "" || *admin == "" {
		log.Fatal("explicit private backend, state directory and admin socket required")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
		log.Fatal("backend must be private IP or loopback")
	}
	g, err := newGate(*dir, *upstream)
	if err != nil {
		log.Fatal("gate initialization failed")
	}
	if err := serve(g, *listen, *admin); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func serve(g *gate, listen, admin string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// RuntimeDirectory removes crash residue. Never unlink another live socket.
	l, err := net.Listen("unix", admin)
	if err != nil {
		return err
	}
	defer l.Close()
	defer os.Remove(admin)
	if err = os.Chmod(admin, 0600); err != nil {
		return err
	}
	control := &http.Server{Handler: http.HandlerFunc(g.admin), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second}
	defer control.Close()
	fail := make(chan error, 2)
	go func() { fail <- control.Serve(l) }()
	fmt.Println("Realm RPC admission ready; processor drain remains an independent check")
	server := &http.Server{Addr: listen, Handler: http.HandlerFunc(g.data), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 210 * time.Second, IdleTimeout: 90 * time.Second}
	defer server.Close()
	go func() { fail <- server.ListenAndServe() }()
	select {
	case err := <-fail:
		return err
	case <-ctx.Done():
	}
	g.mu.Lock()
	g.shuttingDown = true
	g.mu.Unlock()
	if err := g.setMode("closed"); err != nil {
		log.Print("close persistence failed; runtime gate remains closed")
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		return err
	}
	// Shutdown does not await hijacked WebSockets; include response delivery.
	for {
		g.mu.Lock()
		active := g.active + g.wsMessages
		g.mu.Unlock()
		if active == 0 {
			return nil
		}
		select {
		case <-shutdown.Done():
			return shutdown.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
