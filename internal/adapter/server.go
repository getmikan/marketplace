package adapter

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// MaxBody is the largest request body the server reads.
	MaxBody = 1 << 20
	// ProviderTimeout bounds every call to the provider's API.
	ProviderTimeout = 15 * time.Second
)

// HTTPClient is the client for calls to the provider's API.
func HTTPClient() *http.Client { return &http.Client{Timeout: ProviderTimeout} }

// Run serves p on MIKAN_ADAPTER_LISTEN with the MIKAN_ADAPTER_TOKEN Bearer token until
// SIGTERM or SIGINT, then lets the requests in flight finish.
func Run(p Provider) error {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	listen, token := os.Getenv("MIKAN_ADAPTER_LISTEN"), os.Getenv("MIKAN_ADAPTER_TOKEN")
	if err := CheckListen(listen); err != nil {
		return err
	}
	if token == "" {
		return errors.New("MIKAN_ADAPTER_TOKEN is required")
	}
	h, err := NewHandler(p, token, log)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Room for two provider calls (a lookup and a create, or a get and a refund).
		WriteTimeout: 2*ProviderTimeout + 10*time.Second,
		IdleTimeout:  time.Minute,
		ErrorLog:     slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	info := p.Info()
	log.Info("listening", "id", info.ID, "version", info.Version, "listen", listen)
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), srv.WriteTimeout)
	defer cancel()
	return srv.Shutdown(sctx)
}

// CheckListen accepts only a loopback IP address with a fixed port: the adapter must not
// be reachable from outside the host, and the host has to know where it listens.
func CheckListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("MIKAN_ADAPTER_LISTEN %q: want ip:port, e.g. 127.0.0.1:41873", addr)
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() || ip.Zone() != "" {
		return fmt.Errorf("MIKAN_ADAPTER_LISTEN %q: only a loopback address (127.0.0.1 or ::1) is allowed", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("MIKAN_ADAPTER_LISTEN %q: the port must be 1-65535", addr)
	}
	return nil
}

type server struct {
	p        Provider
	refunder Refunder // nil without the refund capability
	info     Info
	tokenSum [sha256.Size]byte
	patterns map[string]*regexp.Regexp
	log      *slog.Logger
}

// NewHandler is the protocol v1 HTTP handler for p. It checks that p's Info is coherent:
// the protocol, setting types and patterns, and the refund capability.
func NewHandler(p Provider, token string, log *slog.Logger) (http.Handler, error) {
	s := &server{p: p, info: p.Info(), tokenSum: sha256.Sum256([]byte(token)), patterns: map[string]*regexp.Regexp{}, log: log}
	if s.info.ID == "" || s.info.Protocol != Protocol {
		return nil, fmt.Errorf("adapter info: id %q, protocol %d", s.info.ID, s.info.Protocol)
	}
	for _, f := range s.info.Settings {
		if f.Type != "string" && f.Type != "bool" {
			return nil, fmt.Errorf("adapter info: setting %s has type %q", f.Key, f.Type)
		}
		if f.Pattern != "" {
			re, err := regexp.Compile(f.Pattern)
			if err != nil {
				return nil, fmt.Errorf("adapter info: setting %s: %w", f.Key, err)
			}
			s.patterns[f.Key] = re
		}
	}
	r, ok := p.(Refunder)
	if slices.Contains(s.info.Capabilities, CapRefund) {
		if !ok {
			return nil, errors.New("adapter info: the refund capability without a Refund method")
		}
		s.refunder = r
	}
	return s, nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	res, err := s.serve(w, r)
	status := http.StatusOK
	attrs := []any{"method", r.Method, "path", r.URL.Path}
	if err != nil {
		var e *Error
		if !errors.As(err, &e) {
			e = unavailable(err)
		}
		status, res = e.Status, e
		attrs = append(attrs, "code", e.Code)
	}
	switch v := res.(type) {
	case Invoice:
		attrs = append(attrs, "external_id", v.ExternalID)
	case webhookAnswer:
		attrs = append(attrs, "external_id", v.ExternalID)
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mikan-adapter"`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(res)
	s.log.Info("request", append(attrs, "status", status, "ms", time.Since(start).Milliseconds())...)
}

// unavailable is a provider call that failed on the way: only its kind is shown, since
// transport errors carry URLs and addresses.
func unavailable(err error) *Error {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return ProviderUnavailable("the provider did not answer in time")
	}
	return ProviderUnavailable("the provider could not be reached")
}

type webhookAnswer struct {
	ExternalID string `json:"external_id,omitempty"`
}

var empty = struct{}{}

func (s *server) serve(w http.ResponseWriter, r *http.Request) (any, error) {
	if !s.authorized(r) {
		return nil, &Error{Status: http.StatusUnauthorized, Code: CodeUnauthorized, Message: "a valid Bearer token is required"}
	}
	method := http.MethodPost
	if r.URL.Path == "/v1/info" {
		method = http.MethodGet
	}
	switch r.URL.Path {
	case "/v1/info", "/v1/check", "/v1/invoices", "/v1/status", "/v1/webhook", "/v1/refund":
		if r.Method != method {
			return nil, &Error{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed", Message: "use " + method}
		}
	default:
		return nil, NotFound("no such endpoint")
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	ctx := r.Context()

	switch r.URL.Path {
	case "/v1/info":
		return s.info, nil

	case "/v1/check":
		var req struct {
			Settings Settings `json:"settings"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		if err := s.checkSettings(req.Settings); err != nil {
			return nil, err
		}
		return empty, s.p.Check(ctx, req.Settings)

	case "/v1/invoices":
		var req InvoiceRequest
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		if err := s.checkSettings(req.Settings); err != nil {
			return nil, err
		}
		if err := s.checkInvoice(req); err != nil {
			return nil, err
		}
		inv, err := s.p.CreateInvoice(ctx, req)
		if err != nil {
			return nil, err
		}
		if inv.ExternalID == "" || inv.PayURL == "" {
			return nil, ProviderUnavailable("the provider gave no invoice")
		}
		return inv, nil

	case "/v1/status":
		var req struct {
			Settings   Settings `json:"settings"`
			ExternalID string   `json:"external_id"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		if err := s.checkSettings(req.Settings); err != nil {
			return nil, err
		}
		if req.ExternalID == "" {
			return nil, BadRequest("external_id is required")
		}
		st, err := s.p.Status(ctx, req.Settings, req.ExternalID)
		if err != nil {
			return nil, err
		}
		if st.Status != StatusPending && st.Status != StatusPaid && st.Status != StatusCanceled {
			return nil, ProviderUnavailable("the provider gave an unknown status")
		}
		return st, nil

	case "/v1/webhook":
		var req WebhookRequest
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		if err := s.checkSettings(req.Settings); err != nil {
			return nil, err
		}
		h := make(http.Header, len(req.Headers))
		for k, vs := range req.Headers {
			for _, v := range vs {
				h.Add(k, v)
			}
		}
		req.Headers = h
		id, err := s.p.Webhook(ctx, req)
		if err != nil {
			return nil, err
		}
		return webhookAnswer{ExternalID: id}, nil

	default: // "/v1/refund"
		if s.refunder == nil {
			return nil, NotFound("this adapter does not refund")
		}
		var req struct {
			Settings   Settings `json:"settings"`
			ExternalID string   `json:"external_id"`
			Amount     int64    `json:"amount"`
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		if err := s.checkSettings(req.Settings); err != nil {
			return nil, err
		}
		if req.ExternalID == "" || req.Amount <= 0 {
			return nil, BadRequest("external_id and a positive amount are required")
		}
		return empty, s.refunder.Refund(ctx, req.Settings, req.ExternalID, req.Amount)
	}
}

// authorized compares the Bearer token in constant time (hashes first, so the length
// does not leak either).
func (s *server) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	got := sha256.Sum256([]byte(h[len(prefix):]))
	return subtle.ConstantTimeCompare(got[:], s.tokenSum[:]) == 1
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return BadRequest("the body is larger than 1 MiB")
		}
		return BadRequest("the body is not valid JSON for this endpoint")
	}
	return nil
}

// checkSettings validates the settings against Info.Settings: presence, type, pattern.
// Keys the adapter does not declare are ignored.
func (s *server) checkSettings(st Settings) error {
	for _, f := range s.info.Settings {
		v, ok := st[f.Key]
		if !ok || v == nil {
			if f.Required {
				return BadSettings(f.Key + " is required")
			}
			continue
		}
		if f.Type == "bool" {
			if _, ok := v.(bool); !ok {
				return BadSettings(f.Key + " must be true or false")
			}
			continue
		}
		str, ok := v.(string)
		switch {
		case !ok:
			return BadSettings(f.Key + " must be a string")
		case str == "" && f.Required:
			return BadSettings(f.Key + " is required")
		case str != "" && s.patterns[f.Key] != nil && !s.patterns[f.Key].MatchString(str):
			return BadSettings(f.Key + " has a wrong format")
		}
	}
	return nil
}

// idempotencyKey is what providers accept as a key: up to 64 printable ASCII characters.
var idempotencyKey = regexp.MustCompile(`^[!-~]{1,64}$`)

func (s *server) checkInvoice(r InvoiceRequest) error {
	switch {
	case r.PaymentID <= 0:
		return BadRequest("payment_id must be positive")
	case !idempotencyKey.MatchString(r.IdempotencyKey):
		return BadRequest("idempotency_key must be 1-64 printable ASCII characters")
	case r.Amount <= 0:
		return BadRequest("amount must be positive (minor units)")
	case !slices.Contains(s.info.Currencies, r.Currency):
		return BadRequest("currency " + strconv.Quote(r.Currency) + " is not supported")
	case !webURL(r.ReturnURL):
		return BadRequest("return_url must be an http(s) URL")
	case !webURL(r.WebhookURL):
		return BadRequest("webhook_url must be an http(s) URL")
	}
	return nil
}

// webURL: empty, or an absolute http(s) URL.
func webURL(s string) bool {
	if s == "" {
		return true
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}
