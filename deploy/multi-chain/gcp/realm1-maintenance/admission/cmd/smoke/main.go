package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	endpoint := flag.String("url", "http://10.148.0.29:21340/", "endpoint")
	closed := flag.Bool("closed", false, "also check rejection of empty-parameter submissions")
	flag.Parse()
	if err := check(*endpoint, *closed); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(`{"http_query":true,"websocket_query":true,"success":true}`)
}

func check(endpoint string, closed bool) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("HTTP URL required")
	}
	requests := []map[string]any{{"jsonrpc": "2.0", "id": 1, "method": "psy_get_latest_checkpoint_id", "params": []any{}}}
	if closed {
		for n, method := range []string{"psy_submit_user_end_cap", "psy_submit_user_end_cap_batch"} {
			requests = append(requests, map[string]any{"jsonrpc": "2.0", "id": n + 2, "method": method, "params": []any{}})
		}
	}
	body, err := json.Marshal(requests)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
	response.Body.Close()
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("HTTP status %d", response.StatusCode)
	}
	validate := func(data []byte) error {
		var replies []struct {
			ID     int     `json:"id"`
			Result *uint64 `json:"result"`
			Error  *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(data, &replies); err != nil {
			return err
		}
		if len(replies) != len(requests) {
			return fmt.Errorf("wrong response count")
		}
		seen := map[int]bool{}
		for _, reply := range replies {
			if seen[reply.ID] {
				return fmt.Errorf("duplicate response ID")
			}
			seen[reply.ID] = true
			if reply.ID == 1 {
				if reply.Result == nil || reply.Error != nil {
					return fmt.Errorf("query failed")
				}
			} else if !closed || (reply.ID != 2 && reply.ID != 3) || reply.Error == nil || reply.Error.Code != -32098 {
				return fmt.Errorf("submission not rejected by gate")
			}
		}
		if !seen[1] {
			return fmt.Errorf("missing query")
		}
		return nil
	}
	if err := validate(data); err != nil {
		return err
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	ws, _, err := dialer.Dial(u.String(), http.Header{"Origin": []string{"https://app-stg.psy-protocol.xyz"}})
	if err != nil {
		return err
	}
	defer ws.Close()
	ws.SetReadLimit(1024 * 1024)
	ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err := ws.WriteMessage(websocket.TextMessage, body); err != nil {
		return err
	}
	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, data, err = ws.ReadMessage()
	if err != nil {
		return err
	}
	return validate(data)
}
