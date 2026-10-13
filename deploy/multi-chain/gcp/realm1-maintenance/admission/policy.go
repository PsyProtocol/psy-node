package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxBody = 512 << 20

type request struct {
	Method string
	ID     json.RawMessage
	Raw    json.RawMessage
}

func isSubmission(method string) bool {
	return method == "psy_submit_user_end_cap" || method == "psy_submit_user_end_cap_batch"
}

// Reject ambiguous top-level fields before forwarding the original bytes.
func parseRequest(raw json.RawMessage) (request, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return request{}, errors.New("request must be an object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		k, err := d.Token()
		if err != nil {
			return request{}, err
		}
		key, ok := k.(string)
		if !ok {
			return request{}, errors.New("invalid key")
		}
		if _, exists := fields[key]; exists {
			return request{}, errors.New("duplicate request field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return request{}, err
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return request{}, err
	}
	var version, method string
	if json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" ||
		json.Unmarshal(fields["method"], &method) != nil || method == "" {
		return request{}, errors.New("invalid jsonrpc or method")
	}
	if id, ok := fields["id"]; ok {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(id))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return request{}, err
		}
		switch value.(type) {
		case nil, string, json.Number:
		default:
			return request{}, errors.New("invalid id")
		}
	}
	return request{Method: method, ID: fields["id"], Raw: raw}, nil
}

func rpcError(id json.RawMessage, code int, message string) json.RawMessage {
	if id == nil {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   any             `json:"error"`
	}{"2.0", id, map[string]any{"code": code, "message": message}})
	return b
}

func sameID(a, b json.RawMessage) bool {
	var x, y any
	dx, dy := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	dx.UseNumber()
	dy.UseNumber()
	if dx.Decode(&x) != nil || dy.Decode(&y) != nil {
		return false
	}
	switch x.(type) {
	case nil, string, json.Number:
		return x == y
	}
	return false
}

type gate struct {
	mu               sync.Mutex
	mode             string
	dir              string
	upstream         string
	client           *http.Client
	active           int
	persistenceError bool
	shuttingDown     bool
	wsMessages       int
	buffers          budget
	readSlots        chan struct{}
	writeSlots       chan struct{}
	wsSlots          chan struct{}
	messageSlots     chan struct{}
	persist          func(string, any) error
	ledgerEntries    int
}

func durableJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func newGate(dir, upstream string) (*gate, error) {
	if err := os.MkdirAll(filepath.Join(dir, "ledger"), 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(dir, "ledger"))
	if err != nil {
		return nil, err
	}
	g := &gate{dir: dir, upstream: upstream, mode: "closed", persist: durableJSON, ledgerEntries: len(entries), messageSlots: make(chan struct{}, 128), readSlots: make(chan struct{}, 32), writeSlots: make(chan struct{}, 4), wsSlots: make(chan struct{}, 128), client: &http.Client{
		Timeout:       180 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("upstream redirect forbidden") },
		Transport:     &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second},
	}}
	data, err := os.ReadFile(filepath.Join(dir, "mode.json"))
	if errors.Is(err, os.ErrNotExist) {
		err = durableJSON(filepath.Join(dir, "mode.json"), map[string]string{"mode": "closed"})
	} else if err == nil {
		var state struct {
			Mode string `json:"mode"`
		}
		if err = json.Unmarshal(data, &state); err == nil {
			if state.Mode != "closed" && state.Mode != "open" {
				err = errors.New("invalid persisted gate mode")
			}
		}
	}
	// Reopening is always an explicit operator action after any restart.
	if err == nil {
		err = durableJSON(filepath.Join(dir, "mode.json"), map[string]string{"mode": "closed"})
	}
	return g, err
}

func (g *gate) setMode(mode string) error {
	if mode != "open" && mode != "closed" {
		return errors.New("invalid mode")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.persistenceError {
		return errors.New("persistence uncertainty requires inspection")
	}
	if mode == "open" && g.shuttingDown {
		return errors.New("shutdown cannot reopen admission")
	}
	// A failed close must still reject new writes in the running process.
	if mode == "closed" {
		g.mode = "closed"
	}
	if err := g.persist(filepath.Join(g.dir, "mode.json"), map[string]any{"mode": mode, "changed_at": time.Now().UTC()}); err != nil {
		g.mode = "closed"
		g.persistenceError = true
		return err
	}
	g.mode = mode
	return nil
}

func (g *gate) one(ctx context.Context, raw json.RawMessage) json.RawMessage {
	r, err := parseRequest(raw)
	if err != nil {
		return rpcError(nil, -32600, "Invalid Request")
	}
	write := isSubmission(r.Method)
	if !write {
		select {
		case g.readSlots <- struct{}{}:
			defer func() { <-g.readSlots }()
		case <-ctx.Done():
			if r.ID == nil {
				return nil
			}
			return rpcError(r.ID, -32099, "RPC deadline expired before forwarding")
		}
	}
	var record map[string]any
	var ledger string
	if write {
		g.mu.Lock()
		if ctx.Err() != nil {
			g.mu.Unlock()
			if r.ID == nil {
				return nil
			}
			return rpcError(r.ID, -32099, "Submission deadline expired before admission")
		}
		if g.mode != "open" || g.persistenceError || g.ledgerEntries >= 50000 {
			g.mu.Unlock()
			if r.ID == nil {
				return nil
			}
			return rpcError(r.ID, -32098, "Realm maintenance: submission was not admitted; retry after maintenance")
		}
		select {
		case g.writeSlots <- struct{}{}:
			defer func() { <-g.writeSlots }()
		default:
			g.mu.Unlock()
			if r.ID == nil {
				return nil
			}
			return rpcError(r.ID, -32099, "Submission capacity busy: request was not admitted")
		}
		var token [16]byte
		_, err = rand.Read(token[:])
		if err == nil {
			ledger = filepath.Join(g.dir, "ledger", hex.EncodeToString(token[:])+".json")
			sum := sha256.Sum256(raw)
			record = map[string]any{"method": r.Method, "request_sha256": fmt.Sprintf("%x", sum), "started_at": time.Now().UTC(), "status": "pending"}
			err = g.persist(ledger, record)
		}
		if err != nil {
			g.mode = "closed"
			g.persistenceError = true
			g.mu.Unlock()
			if r.ID == nil {
				return nil
			}
			return rpcError(r.ID, -32098, "Admission ledger unavailable: submission was not admitted")
		}
		g.active++
		g.ledgerEntries += 2 // Reserve admission and completion; never prune automatically.
		g.mu.Unlock()
		defer func() { g.mu.Lock(); g.active--; g.mu.Unlock() }()
		// Disconnecting a client must not cancel an admitted upstream submission.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithValue(context.Background(), leaseKey{}, ctx.Value(leaseKey{})), 180*time.Second)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, "POST", g.upstream, bytes.NewReader(raw))
	if err != nil {
		return rpcError(r.ID, -32097, "Upstream request could not be created")
	}
	req.Header.Set("Content-Type", "application/json")
	// No idempotency headers and no application-level retry of uncertain writes.
	resp, err := g.client.Do(req)
	var body []byte
	if err == nil {
		defer resp.Body.Close()
		body, err = bufferedRead(ctx, resp.Body, maxBody)
		if len(body) > maxBody {
			err = errors.New("upstream response too large")
		}
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			err = errors.New("upstream HTTP error")
		}
	}
	validReply := false
	if err == nil && r.ID != nil {
		var response map[string]json.RawMessage
		if json.Unmarshal(body, &response) == nil && sameID(response["id"], r.ID) &&
			string(response["jsonrpc"]) == `"2.0"` && (response["result"] != nil || response["error"] != nil) {
			validReply = true
		}
		if !validReply {
			err = errors.New("invalid upstream JSON-RPC response")
		}
	}
	if write && validReply {
		record["status"] = "handler_responded_not_proof_of_chain_inclusion"
		record["finished_at"] = time.Now().UTC()
		if err := g.persist(strings.TrimSuffix(ledger, ".json")+".done.json", record); err != nil {
			// The admission record is immutable; completion is a separate record.
			g.mu.Lock()
			g.mode = "closed"
			g.persistenceError = true
			g.mu.Unlock()
			fmt.Fprintln(os.Stderr, "admission completion recording failed; drain requires inspection")
		}
	}
	if r.ID == nil {
		return nil
	}
	if err != nil {
		return rpcError(r.ID, -32097, "Upstream outcome unavailable; do not assume submission failed or retry blindly")
	}
	return body
}

func (g *gate) dispatch(ctx context.Context, body []byte) []byte {
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	if ctx.Value(leaseKey{}) == nil {
		var l *lease
		ctx, l = g.withLease(ctx)
		defer l.release()
	}
	if !json.Valid(body) {
		return rpcError(nil, -32700, "Parse error")
	}
	trim := bytes.TrimSpace(body)
	if trim[0] != '[' {
		return g.one(ctx, trim)
	}
	var items []json.RawMessage
	d := json.NewDecoder(bytes.NewReader(trim))
	_, _ = d.Token()
	for d.More() {
		if len(items) == maxBatch {
			return rpcError(nil, -32600, "Batch limit exceeded")
		}
		var item json.RawMessage
		if d.Decode(&item) != nil {
			return rpcError(nil, -32600, "Invalid Request")
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return rpcError(nil, -32600, "Invalid Request")
	}
	// Preserve positional result assembly, but do not let a slow write block reads.
	results := make([]json.RawMessage, len(items))
	var wg sync.WaitGroup
	jobs := make(chan int, len(items))
	for i := range items {
		jobs <- i
	}
	close(jobs)
	for worker := 0; worker < min(32, len(items)); worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = g.one(ctx, items[i])
			}
		}()
	}
	wg.Wait()
	responses := make([]json.RawMessage, 0, len(items))
	for _, r := range results {
		if len(r) > 0 {
			responses = append(responses, r)
		}
	}
	if len(responses) == 0 {
		return nil
	}
	out, _ := json.Marshal(responses)
	return out
}
