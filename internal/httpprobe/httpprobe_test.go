// Copyright (c) 2026 prodrom3 / radamic
// Licensed under the MIT License.

package httpprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestExtractTitle(t *testing.T) {
	cases := map[string]string{
		"<html><head><title>Hello World</title></head>":   "Hello World",
		"<TITLE>\n  Spaced\n  Title\n</TITLE>":            "Spaced Title",
		"<title lang=\"en\">Attr Title</title>":           "Attr Title",
		"no title here":                                   "",
		"<title>" + strings.Repeat("x", 300) + "</title>": strings.Repeat("x", 200),
	}
	for in, want := range cases {
		if got := extractTitle([]byte(in)); got != want {
			t.Errorf("extractTitle(%.20q) = %q want %q", in, got, want)
		}
	}
}

func TestDetectTech(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.25.1")
	h.Set("X-Powered-By", "PHP/8.2")
	h.Set("CF-RAY", "abc-DEF")
	body := []byte(`<html><body class="wp-content"><div data-reactroot></div></body></html>`)

	tech := detectTech(h, body)
	joined := strings.Join(tech, ",")
	for _, want := range []string{"Nginx", "PHP", "Cloudflare", "WordPress", "React"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected %q in detected tech, got %v", want, tech)
		}
	}
}

func TestProbeReadsTitleTechAndSendsUserAgent(t *testing.T) {
	var gotUA, gotCustom string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotCustom = r.Header.Get("X-Test")
		w.Header().Set("Server", "nginx")
		w.WriteHeader(200)
		w.Write([]byte("<html><head><title>Probe Me</title></head><body>wp-content</body></html>"))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	res := Probe(context.Background(), nil, host, host, port, 5*time.Second,
		"triton-test/1.0", []string{"X-Test: yes"})

	if res.Error != nil {
		t.Fatalf("probe error: %s", *res.Error)
	}
	if res.StatusCode != 200 {
		t.Errorf("status = %d want 200", res.StatusCode)
	}
	if res.Title == nil || *res.Title != "Probe Me" {
		t.Errorf("title = %v want 'Probe Me'", res.Title)
	}
	if len(res.Tech) == 0 {
		t.Errorf("expected tech detected (nginx/WordPress), got none")
	}
	if gotUA != "triton-test/1.0" {
		t.Errorf("custom User-Agent not sent: %q", gotUA)
	}
	if gotCustom != "yes" {
		t.Errorf("custom header not sent: %q", gotCustom)
	}
}

func TestProbeDefaultUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	Probe(context.Background(), nil, host, host, port, 5*time.Second, "", nil)
	if gotUA != DefaultUserAgent {
		t.Errorf("default User-Agent = %q want %q", gotUA, DefaultUserAgent)
	}
}

func TestCheckSecurityHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=63072000")
	sh := checkSecurityHeaders(h)
	if sh.HSTS == nil {
		t.Error("HSTS should be detected")
	}
	if sh.Missing == nil || !strings.Contains(*sh.Missing, "X-Frame-Options") {
		t.Errorf("expected X-Frame-Options in missing, got %v", sh.Missing)
	}
}

func TestValidHeaderName(t *testing.T) {
	valid := []string{"X-Test", "Authorization", "Content-Type", "x_custom", "A1"}
	for _, s := range valid {
		if !validHeaderName(s) {
			t.Errorf("validHeaderName(%q) = false, want true", s)
		}
	}
	invalid := []string{"", " ", "X Test", "bad:name", "a\tb", "café"}
	for _, s := range invalid {
		if validHeaderName(s) {
			t.Errorf("validHeaderName(%q) = true, want false", s)
		}
	}
}

func TestProbeSkipsMalformedHeader(t *testing.T) {
	var sawGood string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawGood = r.Header.Get("X-Good")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	// A malformed header (": bad") must be skipped, and the probe must still
	// succeed with the valid header applied.
	res := Probe(context.Background(), nil, host, host, port, 5*time.Second, "",
		[]string{": bad", "X-Good: yes"})
	if res.Error != nil {
		t.Fatalf("probe aborted on malformed header: %s", *res.Error)
	}
	if res.StatusCode != 200 {
		t.Errorf("status = %d want 200", res.StatusCode)
	}
	if sawGood != "yes" {
		t.Errorf("valid header not sent alongside the bad one: %q", sawGood)
	}
}

func TestDetectTechRails(t *testing.T) {
	h := http.Header{}
	body := []byte(`<meta name="csrf-param" content="authenticity_token" />`)
	tech := detectTech(h, body)
	found := false
	for _, tt := range tech {
		if tt == "Ruby on Rails" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Ruby on Rails detected via authenticity_token, got %v", tech)
	}
}

func TestExtractTitleRuneTruncation(t *testing.T) {
	long := strings.Repeat("世", 250) // 3 bytes each
	got := extractTitle([]byte("<title>" + long + "</title>"))
	if !utf8.ValidString(got) {
		t.Error("truncated title is not valid UTF-8")
	}
	if n := utf8.RuneCountInString(got); n != 200 {
		t.Errorf("expected 200 runes, got %d", n)
	}
}
