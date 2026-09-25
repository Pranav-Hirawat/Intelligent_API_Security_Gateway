package reputation

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A live feed picks up new entries on its own, without a gateway restart.
func TestARemoteFeedRefreshesInTheBackgroundUntilStopped(t *testing.T) {
	var answer atomic.Value
	answer.Store("192.0.2.7\n")
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_, _ = w.Write([]byte(answer.Load().(string)))
	}))
	defer server.Close()

	feed := New()
	loader := NewLoader(feed)
	src := Source{URL: server.URL, RefreshInterval: 10 * time.Millisecond, Timeout: time.Second}
	if err := loader.Load(src); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	loader.Start(src, stop)

	answer.Store("192.0.2.7\n192.0.2.99\n")
	deadline := time.Now().Add(2 * time.Second)
	for !feed.Contains("192.0.2.99") {
		if time.Now().After(deadline) {
			t.Fatal("the refreshed entry never arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(stop)
	time.Sleep(30 * time.Millisecond)
	settled := fetches.Load()
	time.Sleep(50 * time.Millisecond)
	if fetches.Load() != settled {
		t.Error("the feed kept fetching after it was stopped")
	}
}

// Only the remote half can change, so without a URL and an interval there is
// nothing to refresh and no goroutine is started.
func TestNothingRefreshesWithoutAURLAndAnInterval(t *testing.T) {
	var fetches atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
	}))
	defer server.Close()

	stop := make(chan struct{})
	defer close(stop)
	NewLoader(New()).Start(Source{URL: server.URL}, stop)
	NewLoader(New()).Start(Source{RefreshInterval: time.Millisecond}, stop)
	time.Sleep(30 * time.Millisecond)
	if fetches.Load() != 0 {
		t.Errorf("fetched %d times with no refresh configured", fetches.Load())
	}
}

// A feed that loaded nothing must say so: it looks exactly like a feed where
// no attacker happens to be listed.
func TestDescribeSaysWhatIsLoadedAndFromWhere(t *testing.T) {
	var none *Feed
	if got := none.Describe(); got != "no reputation feed" {
		t.Errorf("nil feed: %q", got)
	}
	if none.Contains("203.0.113.5") || none.Len() != 0 {
		t.Error("a missing feed reported entries")
	}
	empty := New()
	if err := NewLoader(empty).Load(Source{}); err != nil {
		t.Fatal(err)
	}
	if got := empty.Describe(); got != "0 networks from empty" {
		t.Errorf("empty feed: %q", got)
	}
	if !strings.HasPrefix(New().Describe(), "0 networks") {
		t.Errorf("new feed: %q", New().Describe())
	}
}
