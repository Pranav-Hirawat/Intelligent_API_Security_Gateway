package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/netutil"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/policy"
	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/telemetry"
)

type bodyTestPolicies map[string]policy.Decision

func (p bodyTestPolicies) Lookup(ip string) (policy.Decision, bool) {
	d, ok := p[ip]
	return d, ok
}

type forbiddenRead struct{ t *testing.T }

func (b forbiddenRead) Read([]byte) (int, error) {
	b.t.Fatal("an already refused request body was read")
	return 0, nil
}

func (b forbiddenRead) Close() error { return nil }

// oneRequestQuota lets the first call through and refuses the rest, which is
// all this test needs from the Redis bucket production wires.
type oneRequestQuota struct{ taken bool }

func (q *oneRequestQuota) Take(context.Context, policy.QuotaRequest) (policy.QuotaResult, error) {
	if q.taken {
		return policy.QuotaResult{RetryAfter: time.Minute}, nil
	}
	q.taken = true
	return policy.QuotaResult{Allowed: true, Reason: "within_quota"}, nil
}

type bodyTestEvents struct{ events []telemetry.Event }

func (w *bodyTestEvents) WriteEvent(_ context.Context, ev telemetry.Event) error {
	w.events = append(w.events, ev)
	return nil
}

func TestPolicyRefusalsDoNotReadBodiesAndStillProduceTelemetry(t *testing.T) {
	for _, tc := range []struct {
		action string
		status int
	}{
		{policy.ActionTempBlock, http.StatusForbidden},
		{policy.ActionThrottle, http.StatusTooManyRequests},
	} {
		t.Run(tc.action, func(t *testing.T) {
			const ip = "203.0.113.60"
			resolver, err := netutil.NewResolver([]string{"10.0.0.0/8"})
			if err != nil {
				t.Fatal(err)
			}
			enforcer := policy.NewEnforcer(bodyTestPolicies{
				ip: {Action: tc.action, RequestsPerMinute: 1},
			}, true).WithQuotaLimiter(&oneRequestQuota{}, 60, 20)
			writer := &bodyTestEvents{}
			backendCalls := 0
			handler := ChainMiddleware(
				resolver.Middleware,
				telemetry.Middleware(writer, nil, nil, nil),
				enforcer.Middleware,
				BodyLimitMiddleware(16),
				telemetry.CaptureBody,
			)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				backendCalls++
				w.WriteHeader(http.StatusOK)
			}))
			request := func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/login", nil)
				r.RemoteAddr = "10.0.0.1:54321"
				r.Header.Set("X-Forwarded-For", ip)
				return r
			}
			if tc.action == policy.ActionThrottle {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, request())
				if rec.Code != http.StatusOK {
					t.Fatalf("request within quota = %d", rec.Code)
				}
			}
			before := backendCalls
			req := request()
			req.Body = forbiddenRead{t}
			req.ContentLength = -1
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status || backendCalls != before {
				t.Fatalf("refusal status = %d, backend calls = %d; want %d, %d", rec.Code, backendCalls, tc.status, before)
			}
			ev := writer.events[len(writer.events)-1]
			if ev.IP != ip || ev.Status != tc.status || ev.Snippet != "" || ev.RequestID == "" {
				t.Fatalf("refusal event lost trusted IP/status/ID or read a snippet: %+v", ev)
			}
		})
	}
}
