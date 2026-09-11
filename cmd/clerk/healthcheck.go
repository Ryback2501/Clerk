package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// healthcheckTimeout bounds the probe. It runs inside the container on every
// health interval, so it must fail fast rather than pile up.
const healthcheckTimeout = 3 * time.Second

// runHealthcheck probes this container's own health endpoint and reports
// whether it is serving.
//
// It lives in the binary because the runtime image is distroless: there is no
// shell and no curl for a container healthcheck to use.
func runHealthcheck(listenAddr string) error {
	url := "http://" + healthcheckHost(listenAddr) + "/health"

	client := &http.Client{Timeout: healthcheckTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("probe %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe %s: %s", url, resp.Status)
	}
	return nil
}

// healthcheckHost turns a listen address into one that can be dialled.
// A listener bound to all interfaces (":8080" or "0.0.0.0:8080") is reached
// over the loopback address from inside the container.
func healthcheckHost(listenAddr string) string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		// Not host:port at all; fall back to the default port.
		return net.JoinHostPort("127.0.0.1", "8080")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// healthcheckRequested reports whether the process was started to probe rather
// than to serve.
func healthcheckRequested(args []string) bool {
	for _, a := range args {
		if a == "-healthcheck" || a == "--healthcheck" {
			return true
		}
	}
	return false
}

// exitUnhealthy ends the probe with a non-zero status so Docker marks the
// container unhealthy.
func exitUnhealthy(err error) {
	fmt.Fprintln(os.Stderr, "healthcheck failed:", err)
	os.Exit(1)
}
