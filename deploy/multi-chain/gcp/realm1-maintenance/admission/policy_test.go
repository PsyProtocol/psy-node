package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"github.com/gorilla/websocket"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const query = `{"jsonrpc":"2.0","id":18446744073709551615,"method":"psy_get_latest_checkpoint_id","params":[]}`
const submission = `{"jsonrpc":"2.0","id":"write","method":"psy_submit_user_end_cap","params":[]}`

func harness(t *testing.T) (*gate, *[]string, *sync.Mutex) {
	t.Helper()
	methods := []string{}
	mu := &sync.Mutex{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p, err := parseRequest(body)
		if err != nil {
			t.Error(err)
			http.Error(w, "bad", 400)
			return
		}
		mu.Lock()
		methods = append(methods, p.Method)
		mu.Unlock()
		if p.ID == nil {
			w.WriteHeader(204)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(append(append([]byte(`{"jsonrpc":"2.0","id":`), p.ID...), []byte(`,"result":42}`)...))
	}))
	t.Cleanup(s.Close)
	g, err := newGate(t.TempDir(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.client.CloseIdleConnections)
	return g, &methods, mu
}

func status(t *testing.T, g *gate) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	g.admin(w, httptest.NewRequest("GET", "/status", nil))
	var r map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestClosedPolicy(t *testing.T) {
	for _, method := range []string{"psy_submit_user_end_cap", "psy_submit_user_end_cap_batch", "psy_submit_user_end_\\u0063ap"} {
		t.Run(method, func(t *testing.T) {
			g, methods, _ := harness(t)
			body := strings.ReplaceAll(submission, "psy_submit_user_end_cap", method)
			out := g.dispatch(context.Background(), []byte(body))
			if !bytes.Contains(out, []byte("-32098")) || len(*methods) != 0 {
				t.Fatalf("not blocked: %s %v", out, *methods)
			}
		})
	}
}

func TestReadAndWorkerMethodsPass(t *testing.T) {
	for _, method := range []string{"psy_get_latest_checkpoint_id", "psy_get_user_leaf_data", "psy_fetch_job", "psy_submit_proof", "psy_get_user_end_cap_slot_updates"} {
		t.Run(method, func(t *testing.T) {
			g, m, _ := harness(t)
			out := g.dispatch(context.Background(), []byte(strings.ReplaceAll(query, "psy_get_latest_checkpoint_id", method)))
			if len(*m) != 1 || !bytes.Contains(out, []byte(`"result":42`)) || !bytes.Contains(out, []byte("18446744073709551615")) {
				t.Fatalf("%s %v", out, *m)
			}
		})
	}
}

func TestMixedBatchKeepsRead(t *testing.T) {
	g, m, _ := harness(t)
	out := g.dispatch(context.Background(), []byte("["+submission+","+query+",false]"))
	var replies []json.RawMessage
	if json.Unmarshal(out, &replies) != nil || len(replies) != 3 {
		t.Fatalf("%s", out)
	}
	if len(*m) != 1 || (*m)[0] != "psy_get_latest_checkpoint_id" {
		t.Fatal(*m)
	}
	if !bytes.Contains(replies[0], []byte("-32098")) || !bytes.Contains(replies[1], []byte(`"result":42`)) || !bytes.Contains(replies[2], []byte("-32600")) {
		t.Fatalf("%s", out)
	}
}

func TestRejectAmbiguousAndMalformed(t *testing.T) {
	for _, body := range []string{`{`, `[]`, `null`, `{"jsonrpc":"2.0","method":"psy_get_latest_checkpoint_id","method":"psy_submit_user_end_cap","id":1}`, `{"jsonrpc":"2.0","method":"psy_submit_user_end_cap","method":"psy_get_latest_checkpoint_id","id":1}`, `{"jsonrpc":"2.0","id":[],"method":"read"}`} {
		t.Run(body, func(t *testing.T) {
			g, m, _ := harness(t)
			out := g.dispatch(context.Background(), []byte(body))
			if len(*m) != 0 || !bytes.Contains(out, []byte(`"error"`)) {
				t.Fatalf("%s", out)
			}
		})
	}
}

func TestNotifications(t *testing.T) {
	g, m, _ := harness(t)
	blocked := strings.ReplaceAll(submission, `"id":"write",`, "")
	if out := g.dispatch(context.Background(), []byte(blocked)); len(out) != 0 || len(*m) != 0 {
		t.Fatal(string(out), *m)
	}
	read := strings.ReplaceAll(query, `"id":18446744073709551615,`, "")
	if out := g.dispatch(context.Background(), []byte("["+read+","+blocked+"]")); len(out) != 0 || len(*m) != 1 {
		t.Fatal(string(out), *m)
	}
}

func TestOpenAndRestartPersistence(t *testing.T) {
	g, m, _ := harness(t)
	if err := g.setMode("open"); err != nil {
		t.Fatal(err)
	}
	if out := g.dispatch(context.Background(), []byte(submission)); !bytes.Contains(out, []byte(`"result"`)) || len(*m) != 1 {
		t.Fatalf("%s", out)
	}
	if err := g.setMode("closed"); err != nil {
		t.Fatal(err)
	}
	restarted, err := newGate(g.dir, g.upstream)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.client.CloseIdleConnections()
	if restarted.mode != "closed" {
		t.Fatal(restarted.mode)
	}
	s := status(t, restarted)
	if s["responded"] != float64(1) || s["pending_or_ambiguous"] != float64(0) || s["safe_to_stop_processor"] != false {
		t.Fatal(s)
	}
}

func TestUpstreamFailureNeverRetriesAndLeavesLedger(t *testing.T) {
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; http.Error(w, "bad", 502) }))
	defer s.Close()
	g, err := newGate(t.TempDir(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer g.client.CloseIdleConnections()
	g.setMode("open")
	out := g.dispatch(context.Background(), []byte(submission))
	if calls != 1 || !bytes.Contains(out, []byte("-32097")) {
		t.Fatal(calls, string(out))
	}
	if status(t, g)["pending_or_ambiguous"] != float64(1) {
		t.Fatal(status(t, g))
	}
	files, _ := os.ReadDir(filepath.Join(g.dir, "ledger"))
	data, _ := os.ReadFile(filepath.Join(g.dir, "ledger", files[0].Name()))
	if bytes.Contains(data, []byte(`"params"`)) {
		t.Fatal("raw request leaked into ledger")
	}
}

func TestCloseWithInflightAndClientCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		p, _ := parseRequest(body)
		if isSubmission(p.Method) {
			close(entered)
			<-release
		}
		w.Write(append(append([]byte(`{"jsonrpc":"2.0","id":`), p.ID...), []byte(`,"result":42}`)...))
	}))
	defer s.Close()
	g, err := newGate(t.TempDir(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer g.client.CloseIdleConnections()
	g.setMode("open")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []byte, 1)
	go func() { done <- g.dispatch(ctx, []byte(submission)) }()
	<-entered
	cancel()
	g.setMode("closed")
	if status(t, g)["active_submissions"] != float64(1) {
		t.Fatal(status(t, g))
	}
	if out := g.dispatch(context.Background(), []byte(submission)); !bytes.Contains(out, []byte("-32098")) {
		t.Fatalf("%s", out)
	}
	if out := g.dispatch(context.Background(), []byte(query)); !bytes.Contains(out, []byte(`"result"`)) {
		t.Fatalf("%s", out)
	}
	close(release)
	select {
	case out := <-done:
		if !bytes.Contains(out, []byte(`"result"`)) {
			t.Fatalf("%s", out)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("inflight failed")
	}
	if status(t, g)["active_submissions"] != float64(0) {
		t.Fatal(status(t, g))
	}
}

func TestGzipAndAdminNotExposed(t *testing.T) {
	g, m, _ := harness(t)
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	z.Write([]byte("[" + submission + "," + query + "]"))
	z.Close()
	r := httptest.NewRequest("POST", "/", &b)
	r.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	g.data(w, r)
	if w.Code != 200 || len(*m) != 1 || !bytes.Contains(w.Body.Bytes(), []byte("-32098")) {
		t.Fatal(w.Code, w.Body.String(), *m)
	}
	r = httptest.NewRequest("PUT", "/mode", strings.NewReader(`{"mode":"open"}`))
	w = httptest.NewRecorder()
	g.data(w, r)
	if w.Code != 405 || g.mode != "closed" {
		t.Fatal(w.Code, g.mode)
	}
}

func TestExistingWebSocketHonorsClose(t *testing.T) {
	g, m, mu := harness(t)
	g.setMode("open")
	s := httptest.NewServer(http.HandlerFunc(g.data))
	defer s.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(s.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := c.WriteMessage(websocket.TextMessage, []byte(query)); err != nil {
		t.Fatal(err)
	}
	if _, b, err := c.ReadMessage(); err != nil || !bytes.Contains(b, []byte(`"result"`)) {
		t.Fatal(string(b), err)
	}
	g.setMode("closed")
	c.WriteMessage(websocket.TextMessage, []byte("["+submission+","+query+"]"))
	_, b, err := c.ReadMessage()
	if err != nil || !bytes.Contains(b, []byte("-32098")) || !bytes.Contains(b, []byte(`"result"`)) {
		t.Fatal(string(b), err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*m) != 2 {
		t.Fatal(*m)
	}
}

func TestStringIDEscapesCompareSemantically(t *testing.T) {
	if !sameID(json.RawMessage(`"a"`), json.RawMessage(`"\u0061"`)) {
		t.Fatal("escaped id rejected")
	}
	if sameID(json.RawMessage(`1`), json.RawMessage(`"1"`)) {
		t.Fatal("distinct ids conflated")
	}
}
