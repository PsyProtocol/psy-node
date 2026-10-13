package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRestartNeverRestoresOpen(t *testing.T) {
	g, _, _ := harness(t)
	if err := g.setMode("open"); err != nil {
		t.Fatal(err)
	}
	restarted, err := newGate(g.dir, g.upstream)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.client.CloseIdleConnections()
	if restarted.mode != "closed" {
		t.Fatal("restart reopened admission")
	}
}

func TestShutdownCannotReopen(t *testing.T) {
	g, _, _ := harness(t)
	g.shuttingDown = true
	if err := g.setMode("open"); err == nil {
		t.Fatal("shutdown reopened admission")
	}
}

func TestServeLifecycle(t *testing.T) {
	if dir := os.Getenv("REALM_ADMISSION_TEST_CHILD"); dir != "" {
		g, err := newGate(dir, "http://127.0.0.1:1/")
		if err != nil {
			os.Exit(2)
		}
		if err := serve(g, "127.0.0.1:0", filepath.Join(dir, "admin.sock")); err != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestServeLifecycle$")
	cmd.Env = append(os.Environ(), "REALM_ADMISSION_TEST_CHILD="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer cmd.Process.Kill()
	socket := filepath.Join(dir, "admin.sock")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("control socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("graceful exit timed out")
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatal("control socket survived exit")
	}
	g, err := newGate(dir, "http://127.0.0.1:1/")
	if err != nil {
		t.Fatal(err)
	}
	defer g.client.CloseIdleConnections()
	if g.mode != "closed" {
		t.Fatal("restart did not stay closed")
	}
}

func TestPersistenceUncertaintyFailsClosed(t *testing.T) {
	for _, afterRename := range []bool{false, true} {
		for _, point := range []string{"admission", "completion", "close"} {
			t.Run(point+map[bool]string{false: "-before", true: "-after"}[afterRename], func(t *testing.T) {
				g, methods, _ := harness(t)
				if err := g.setMode("open"); err != nil {
					t.Fatal(err)
				}
				g.persist = func(path string, value any) error {
					fail := point == "close" && strings.HasSuffix(path, "mode.json") ||
						point == "admission" && !strings.HasSuffix(path, "mode.json") && !strings.HasSuffix(path, ".done.json") ||
						point == "completion" && strings.HasSuffix(path, ".done.json")
					if !fail || afterRename {
						if err := durableJSON(path, value); err != nil {
							return err
						}
					}
					if fail {
						return errors.New("injected persistence failure")
					}
					return nil
				}
				if point == "close" {
					if g.setMode("closed") == nil {
						t.Fatal("failure hidden")
					}
				} else {
					g.dispatch(context.Background(), []byte(submission))
				}
				if g.mode != "closed" || !g.persistenceError {
					t.Fatal("uncertainty not latched")
				}
				if g.setMode("open") == nil {
					t.Fatal("reopened with uncertain persistence")
				}
				if point == "admission" && len(*methods) != 0 {
					t.Fatal("unrecorded write forwarded")
				}
				if point == "completion" {
					entries, err := os.ReadDir(filepath.Join(g.dir, "ledger"))
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, e := range entries {
						if strings.HasSuffix(e.Name(), ".done.json") {
							continue
						}
						data, err := os.ReadFile(filepath.Join(g.dir, "ledger", e.Name()))
						if err != nil {
							t.Fatal(err)
						}
						found = bytes.Contains(data, []byte(`"status":"pending"`))
					}
					if !found {
						t.Fatal("original admission was overwritten")
					}
				}
				restarted, err := newGate(g.dir, g.upstream)
				if err != nil {
					t.Fatal(err)
				}
				defer restarted.client.CloseIdleConnections()
				if restarted.mode != "closed" {
					t.Fatal("restart reopened after persistence failure")
				}
			})
		}
	}
}

func TestBufferBudgetAndSmallMessageReserve(t *testing.T) {
	g, _, _ := harness(t)
	ctx, l := g.withLease(context.Background())
	if err := l.reserve((bufferBudget-smallMessageReserve)/8, true); err != nil {
		t.Fatal(err)
	}
	if err := l.reserve(1, true); err == nil {
		t.Fatal("large message consumed query reserve")
	}
	if err := l.reserve(100, false); err != nil {
		t.Fatal("small message reserve unavailable")
	}
	l.release()
	if g.buffers.used != 0 {
		t.Fatal("budget leaked")
	}
	if _, err := bufferedRead(ctx, strings.NewReader("abcdef"), 5); err == nil {
		t.Fatal("size limit ignored")
	}
	l.release()
	if g.buffers.used != 0 {
		t.Fatal("failed read leaked budget")
	}
}

func TestHTTPReleasesBudgetAndCors(t *testing.T) {
	g, _, _ := harness(t)
	w := httptest.NewRecorder()
	g.data(w, httptest.NewRequest("POST", "/", strings.NewReader(query)))
	if w.Code != 200 || g.buffers.used != 0 || len(g.messageSlots) != 0 {
		t.Fatal("request budget not released", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("missing CORS")
	}
	w = httptest.NewRecorder()
	g.data(w, httptest.NewRequest("OPTIONS", "/", nil))
	if w.Code != 204 || !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "Content-Type") {
		t.Fatal("preflight failed")
	}
}

func TestLimitsRefuseBeforeUpstream(t *testing.T) {
	g, methods, _ := harness(t)
	batch := "[" + strings.Repeat(query+",", maxBatch) + query + "]"
	if !bytes.Contains(g.dispatch(context.Background(), []byte(batch)), []byte("-32600")) || len(*methods) != 0 {
		t.Fatal("batch cap ignored")
	}
	for i := 0; i < cap(g.messageSlots); i++ {
		g.messageSlots <- struct{}{}
	}
	w := httptest.NewRecorder()
	g.data(w, httptest.NewRequest("POST", "/", strings.NewReader(query)))
	if w.Code != 503 || len(*methods) != 0 {
		t.Fatal("message cap ignored")
	}
	if err := g.setMode("open"); err != nil {
		t.Fatal(err)
	}
	g.ledgerEntries = 50000
	if !bytes.Contains(g.dispatch(context.Background(), []byte(submission)), []byte("-32098")) || len(*methods) != 0 {
		t.Fatal("ledger cap ignored")
	}
}

func TestBatchLimitBeforeExpansion(t *testing.T) {
	g, methods, _ := harness(t)
	body := []byte("[" + strings.Repeat("0,", 100000) + "0]")
	allocs := testing.AllocsPerRun(1, func() {
		out := g.dispatch(context.Background(), body)
		if !bytes.Contains(out, []byte("Batch limit exceeded")) {
			t.Fatal(string(out))
		}
	})
	if allocs > 5000 || len(*methods) != 0 {
		t.Fatal("oversized batch expanded before rejection", allocs)
	}
}

func TestLargeValidQueryBatchWaitsForCapacity(t *testing.T) {
	g, methods, _ := harness(t)
	body := []byte("[" + strings.Repeat(query+",", 63) + query + "]")
	out := g.dispatch(context.Background(), body)
	if len(*methods) != 64 || bytes.Count(out, []byte(`"result":42`)) != 64 || bytes.Contains(out, []byte(`"error"`)) {
		t.Fatalf("batch queries rejected: %s", out)
	}
}

func TestQueuedSubmissionExpiresBeforeAdmission(t *testing.T) {
	g, methods, _ := harness(t)
	if err := g.setMode("open"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cap(g.readSlots); i++ {
		g.readSlots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	out := g.dispatch(ctx, []byte("["+strings.Repeat(query+",", 32)+submission+"]"))
	if len(*methods) != 0 || !bytes.Contains(out, []byte("Submission deadline expired before admission")) {
		t.Fatal("expired queued write admitted", string(out))
	}
	if status(t, g)["responded"] != float64(0) || status(t, g)["pending_or_ambiguous"] != float64(0) {
		t.Fatal("expired write created admission")
	}
}

func TestWebSocketQueryNotQueuedBehindSlowSubmissions(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var once sync.Once
	unlock := func() { once.Do(func() { close(release) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		p, _ := parseRequest(b)
		if isSubmission(p.Method) {
			entered <- struct{}{}
			<-release
		}
		w.Write(append(append([]byte(`{"jsonrpc":"2.0","id":`), p.ID...), []byte(`,"result":42}`)...))
	}))
	defer upstream.Close()
	defer unlock()
	g, err := newGate(t.TempDir(), upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer g.client.CloseIdleConnections()
	if err := g.setMode("open"); err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(g.data))
	defer s.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(s.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 4; i++ {
		if err := c.WriteMessage(websocket.TextMessage, []byte(submission)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			t.Fatal("writes not in flight")
		}
	}
	if err := g.setMode("closed"); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteMessage(websocket.TextMessage, []byte(query)); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, b, err := c.ReadMessage()
	if err != nil || !bytes.Contains(b, []byte("18446744073709551615")) {
		t.Fatal("query waited behind slow writes", string(b), err)
	}
	unlock()
	for i := 0; i < 4; i++ {
		if _, _, err := c.ReadMessage(); err != nil {
			t.Fatal(err)
		}
	}
}
