package signals

import (
	"fmt"
	"net/http"
	"time"
)

// printAlert is the console banner the detectors that only observe share. The
// wording of ACTION is the point of it: an operator reading the log must never
// take a banner for a refusal.
func printAlert(title, label, value, ip string, r *http.Request) {
	fmt.Printf(`
		========================================
		SECURITY ALERT: %s
		----------------------------------------
		IP Address     : %s
		Method         : %s
		Endpoint       : %s
		User-Agent     : %s
		%-14s : %s
		Timestamp      : %s
		ACTION         : DETECTED (ALLOWING REQUEST)
		========================================
		`,
		title,
		ip,
		r.Method,
		r.URL.Path,
		r.Header.Get("User-Agent"),
		label, value,
		time.Now().Format(time.RFC3339),
	)
}
