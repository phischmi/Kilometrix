package server

import (
	_ "embed" // für request.html
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	netmail "net/mail"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/phischmi/kilometrix/internal/config"
	"github.com/phischmi/kilometrix/internal/mail"
	"github.com/phischmi/kilometrix/internal/tokens"
)

//go:embed request.html
var requestPage []byte

// approvalTTL: so lange bleibt der Freigabe-Link in der Admin-Mail gültig.
const approvalTTL = 14 * 24 * time.Hour

// requestsEnabled: Das Token-Antragsformular gibt es nur, wenn Auth, SMTP, Admin-Adresse
// und die öffentliche URL (für die Links in Mails) konfiguriert sind.
func requestsEnabled(s config.Settings) bool {
	return s.AuthEnabled && s.AuthSecret != "" && s.SMTPHost != "" && s.MailFrom != "" &&
		s.AdminEmail != "" && s.PublicBaseURL != ""
}

// limiter ist ein einfacher In-Memory-Zähler (Zeitfenster pro Schlüssel).
type limiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{hits: map[string][]time.Time{}, max: max, window: window}
}

// allow zählt einen Treffer und sagt, ob er noch im Limit liegt.
func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cut := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

type requestLimits struct {
	perIP, perEmail, global *limiter
}

func newRequestLimits() *requestLimits {
	return &requestLimits{
		perIP:    newLimiter(5, time.Hour),
		perEmail: newLimiter(3, 24*time.Hour),
		global:   newLimiter(100, 24*time.Hour),
	}
}

// clientIP: hinter Traefik steht der echte Client im ersten X-Forwarded-For-Eintrag.
func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		first, _, _ := strings.Cut(xf, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// cleanName: 2–100 Zeichen, keine Steuerzeichen.
func cleanName(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), " ")
	n := utf8.RuneCountInString(s)
	if n < 2 || n > 100 {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

// cleanEmail: genau eine reine Adresse (kein "Name <a@b>"), mit Domain, max. 254 Zeichen.
func cleanEmail(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 254 || strings.ContainsAny(s, "\r\n<>,;\"") {
		return "", false
	}
	a, err := netmail.ParseAddress(s)
	if err != nil || a.Address != s || !strings.Contains(s[strings.LastIndex(s, "@"):], ".") {
		return "", false
	}
	return strings.ToLower(s), true
}

func (s *Server) domainAllowed(email string) bool {
	_, dom, _ := strings.Cut(email, "@")
	for _, d := range s.settings.AllowedDomains {
		if dom == d {
			return true
		}
	}
	return false
}

func (s *Server) tokenTTL() time.Duration {
	days := s.settings.TokenDays
	if days <= 0 {
		days = 90
	}
	return time.Duration(days) * 24 * time.Hour
}

func securePage(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}

func (s *Server) handleRequestPage(w http.ResponseWriter, _ *http.Request) {
	securePage(w)
	_, _ = w.Write(requestPage)
}

type requestBody struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Website string `json:"website"` // Honeypot: echte Nutzer lassen das Feld leer
}

// handleRequestToken nimmt einen Antrag entgegen. Die Antwort ist bewusst immer gleich
// (auch bei Honeypot/Allowlist), damit sich daraus nichts über die Konfiguration ableiten lässt.
func (s *Server) handleRequestToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	var in requestBody
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "Ungültige Anfrage.")
		return
	}
	ok := map[string]any{"ok": true}
	if in.Website != "" { // Bot: stillschweigend „erfolgreich“
		writeJSON(w, http.StatusOK, ok)
		return
	}
	name, nameOK := cleanName(in.Name)
	email, emailOK := cleanEmail(in.Email)
	if !nameOK || !emailOK {
		writeError(w, http.StatusUnprocessableEntity, "Bitte Name und eine gültige Mailadresse angeben.")
		return
	}
	if !s.limits.perIP.allow(clientIP(r)) || !s.limits.perEmail.allow(email) || !s.limits.global.allow("all") {
		writeError(w, http.StatusTooManyRequests, "Zu viele Anfragen. Bitte später erneut versuchen.")
		return
	}

	var err error
	if s.domainAllowed(email) {
		err = s.sendToken(name, email)
	} else {
		err = s.sendApprovalRequest(name, email)
	}
	if err != nil {
		log.Printf("Token-Antrag: Mailversand fehlgeschlagen: %v", err)
		writeError(w, http.StatusBadGateway, "Die Mail konnte nicht versendet werden. Bitte später erneut versuchen.")
		return
	}
	writeJSON(w, http.StatusOK, ok)
}

// sendApprovalRequest schickt dir die Freigabe-Mail mit signiertem Link.
func (s *Server) sendApprovalRequest(name, email string) error {
	link := s.settings.PublicBaseURL + "/approve?t=" +
		url.QueryEscape(tokens.MintApproval(s.authSecret, name, email, approvalTTL))
	return s.mailer.Send(mail.Message{
		To:      s.settings.AdminEmail,
		ReplyTo: email,
		Subject: "Kilometrix: Token-Antrag von " + name,
		Body: fmt.Sprintf("Neuer Token-Antrag:\n\nName:  %s\nMail:  %s\n\n"+
			"Zum Freigeben (%d Tage) diesen Link öffnen und dort bestätigen:\n%s\n\n"+
			"Zum Ablehnen die Mail einfach ignorieren. Der Link ist %d Tage gültig.\n",
			name, email, s.settings.TokenDays, link, int(approvalTTL.Hours()/24)),
	})
}

// sendToken stellt das Token aus und schickt es an den Antragsteller.
func (s *Server) sendToken(name, email string) error {
	ttl := s.tokenTTL()
	token := tokens.Mint(s.authSecret, name, ttl)
	until := time.Now().Add(ttl).Format("02.01.2006")
	return s.mailer.Send(mail.Message{
		To:      email,
		Subject: "Dein Kilometrix-Zugangstoken",
		Body: fmt.Sprintf("Hallo %s,\n\ndein Zugangstoken für Kilometrix (gültig bis %s):\n\n%s\n\n"+
			"So geht's:\n1. Excel öffnen und das Kilometrix-Add-in starten.\n"+
			"2. Das Token im Feld „Zugang“ einfügen und auf „Verbinden“ klicken.\n\n"+
			"Bitte das Token nicht weitergeben.\n", name, until, token),
	})
}

// --- Freigabe durch den Admin -------------------------------------------------------

var approveTmpl = template.Must(template.New("approve").Parse(`<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kilometrix – Freigabe</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:28rem;margin:0 auto;padding:2rem 1rem;color:#1b1f24}
button{font:inherit;padding:.7rem 1.2rem;border:0;border-radius:.5rem;background:#0b5fff;color:#fff;width:100%}
dl{margin:1rem 0}dt{color:#667;font-size:.85rem}dd{margin:0 0 .6rem;font-weight:600;word-break:break-all}
@media(prefers-color-scheme:dark){body{background:#14171c;color:#e8eaed}}</style></head><body>
<h1>Token freigeben</h1>
{{if .Err}}<p>{{.Err}}</p>{{else if .Done}}<p>✅ Token wurde an <b>{{.Email}}</b> gesendet.</p>
{{else}}<dl><dt>Name</dt><dd>{{.Name}}</dd><dt>Mail</dt><dd>{{.Email}}</dd><dt>Gültigkeit</dt><dd>{{.Days}} Tage</dd></dl>
<form method="post" action="/approve"><input type="hidden" name="t" value="{{.T}}">
<button type="submit">Freigeben &amp; Token senden</button></form>{{end}}
</body></html>`))

type approveView struct {
	Err, Name, Email, T string
	Days                int
	Done                bool
}

func (s *Server) renderApprove(w http.ResponseWriter, status int, v approveView) {
	securePage(w)
	w.WriteHeader(status)
	_ = approveTmpl.Execute(w, v)
}

// handleApprovePage (GET) zeigt nur die Bestätigung — ausgelöst wird erst per POST, damit
// Mail-Scanner, die Links vorab abrufen, nichts freigeben.
func (s *Server) handleApprovePage(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("t")
	a, err := tokens.VerifyApproval(s.authSecret, t)
	if err != nil {
		s.renderApprove(w, http.StatusBadRequest, approveView{Err: err.Error()})
		return
	}
	s.renderApprove(w, http.StatusOK, approveView{Name: a.Name, Email: a.Email, T: t, Days: s.settings.TokenDays})
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		s.renderApprove(w, http.StatusBadRequest, approveView{Err: "Ungültige Anfrage."})
		return
	}
	t := r.PostForm.Get("t")
	a, err := tokens.VerifyApproval(s.authSecret, t)
	if err != nil {
		s.renderApprove(w, http.StatusBadRequest, approveView{Err: err.Error()})
		return
	}
	// Doppelklick-Schutz (bis zum nächsten Neustart): derselbe Antrag wird nur einmal bedient.
	if !s.markApproved(t) {
		s.renderApprove(w, http.StatusOK, approveView{Done: true, Email: a.Email})
		return
	}
	if err := s.sendToken(a.Name, a.Email); err != nil {
		s.unmarkApproved(t)
		log.Printf("Freigabe: Mailversand fehlgeschlagen: %v", err)
		s.renderApprove(w, http.StatusBadGateway, approveView{Err: "Mailversand fehlgeschlagen. Bitte erneut versuchen."})
		return
	}
	s.renderApprove(w, http.StatusOK, approveView{Done: true, Email: a.Email})
}

func (s *Server) markApproved(t string) bool {
	s.approvedMu.Lock()
	defer s.approvedMu.Unlock()
	if s.approved[t] {
		return false
	}
	s.approved[t] = true
	return true
}

func (s *Server) unmarkApproved(t string) {
	s.approvedMu.Lock()
	delete(s.approved, t)
	s.approvedMu.Unlock()
}
