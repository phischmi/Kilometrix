package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/phischmi/kilometrix/internal/config"
	"github.com/phischmi/kilometrix/internal/mail"
	"github.com/phischmi/kilometrix/internal/tokens"
)

// fakeMailer sammelt Mails statt sie zu versenden.
type fakeMailer struct{ sent []mail.Message }

func (f *fakeMailer) Send(m mail.Message) error { f.sent = append(f.sent, m); return nil }

func requestServer() (*Server, *fakeMailer) {
	s := config.Settings{
		MaxSyncBatch: 10, Workers: 1, AddinDir: ".",
		AuthEnabled: true, AuthSecret: "geheim", SMTPHost: "smtp.example", MailFrom: "k@example.de",
		AdminEmail: "admin@example.de", PublicBaseURL: "https://k.example.de",
		AllowedDomains: []string{"firma.de"}, TokenDays: 90,
	}
	srv := New(s, nil, "", nil)
	fm := &fakeMailer{}
	srv.mailer = fm
	return srv, fm
}

func postJSON(srv *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/request-token", strings.NewReader(body))
	req.RemoteAddr = "1.2.3.4:5555"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestUnknownDomainSendsApprovalToAdmin(t *testing.T) {
	srv, fm := requestServer()
	rec := postJSON(srv, `{"name":"Max Muster","email":"max@extern.de"}`)
	if rec.Code != 200 || len(fm.sent) != 1 || fm.sent[0].To != "admin@example.de" {
		t.Fatalf("code %d, mails %+v", rec.Code, fm.sent)
	}
	if strings.Contains(fm.sent[0].Body, "geheim") {
		t.Fatal("Secret in Mail")
	}
	if !regexp.MustCompile(`https://k\.example\.de/approve\?t=`).MatchString(fm.sent[0].Body) {
		t.Fatalf("kein Freigabe-Link: %s", fm.sent[0].Body)
	}
}

func TestAllowedDomainGetsTokenDirectly(t *testing.T) {
	srv, fm := requestServer()
	rec := postJSON(srv, `{"name":"Erika","email":"Erika@Firma.de"}`)
	if rec.Code != 200 || len(fm.sent) != 1 || fm.sent[0].To != "erika@firma.de" {
		t.Fatalf("code %d, mails %+v", rec.Code, fm.sent)
	}
	tok := regexp.MustCompile(`\S+\.\S+`).FindAllString(fm.sent[0].Body, -1)
	ok := false
	for _, c := range tok {
		if cl, err := tokens.Verify("geheim", c); err == nil && cl.Sub == "Erika" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("kein gültiges Token in Mail: %s", fm.sent[0].Body)
	}
}

func TestValidationHoneypotAndLimits(t *testing.T) {
	srv, fm := requestServer()
	for _, body := range []string{
		`{"name":"","email":"a@b.de"}`,
		`{"name":"Max","email":"max"}`,
		`{"name":"Max","email":"a@b.de\r\nBcc: x@y.de"}`,
		`{"name":"Max","email":"Evil <a@b.de>"}`,
	} {
		if rec := postJSON(srv, body); rec.Code != 422 {
			t.Errorf("%s -> %d", body, rec.Code)
		}
	}
	if rec := postJSON(srv, `{"name":"Bot","email":"a@b.de","website":"x"}`); rec.Code != 200 || len(fm.sent) != 0 {
		t.Fatal("Honeypot muss still ignoriert werden")
	}
	// Pro IP max. 5 Anträge pro Stunde.
	var last int
	for i := 0; i < 7; i++ {
		last = postJSON(srv, `{"name":"Max","email":"u`+string(rune('a'+i))+`@extern.de"}`).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("Rate-Limit greift nicht: %d", last)
	}
}

func TestApproveFlow(t *testing.T) {
	srv, fm := requestServer()
	link := tokens.MintApproval("geheim", "Max Muster", "max@extern.de", approvalTTL)

	// GET löst nichts aus.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/approve?t="+url.QueryEscape(link), nil))
	if rec.Code != 200 || len(fm.sent) != 0 || !strings.Contains(rec.Body.String(), "Max Muster") {
		t.Fatalf("GET: %d, %d Mails", rec.Code, len(fm.sent))
	}
	// POST gibt frei — und nur einmal.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/approve", strings.NewReader(url.Values{"t": {link}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec = httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("POST %d: %d", i, rec.Code)
		}
	}
	if len(fm.sent) != 1 || fm.sent[0].To != "max@extern.de" {
		t.Fatalf("Mails: %+v", fm.sent)
	}
	// Manipulierter Link und Zugangstoken als Link werden abgelehnt.
	for _, bad := range []string{link + "x", tokens.Mint("geheim", "Max", 1<<40)} {
		rec = httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/approve?t="+url.QueryEscape(bad), nil))
		if rec.Code != 400 {
			t.Errorf("ungültiger Link akzeptiert: %d", rec.Code)
		}
	}
}

func TestRootRedirectsWithoutMailConfig(t *testing.T) {
	rec := httptest.NewRecorder()
	testServer(nil, nil).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("erwartet Redirect, war %d", rec.Code)
	}
}
