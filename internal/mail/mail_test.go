package mail

import (
	"io"
	"mime"
	"mime/multipart"
	netmail "net/mail"
	"strings"
	"testing"
)

func TestBuildMessageMultipartWithInlineLogo(t *testing.T) {
	from, _ := netmail.ParseAddress("k@example.de")
	to, _ := netmail.ParseAddress("a@example.de")
	raw := buildMessage(from, to, Message{Subject: "Größe", Body: "text", HTML: "<p>html</p>", Logo: []byte("PNG")})

	msg, err := netmail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if mt != "multipart/alternative" {
		t.Fatalf("Content-Type %s", mt)
	}
	alt := multipart.NewReader(msg.Body, params["boundary"])
	p1, _ := alt.NextPart()
	if !strings.HasPrefix(p1.Header.Get("Content-Type"), "text/plain") {
		t.Fatal("erster Teil muss text/plain sein")
	}
	p2, _ := alt.NextPart()
	mt2, params2, _ := mime.ParseMediaType(p2.Header.Get("Content-Type"))
	if mt2 != "multipart/related" {
		t.Fatalf("zweiter Teil %s", mt2)
	}
	rel := multipart.NewReader(p2, params2["boundary"])
	h, _ := rel.NextPart()
	i, _ := rel.NextPart()
	if !strings.HasPrefix(h.Header.Get("Content-Type"), "text/html") || i.Header.Get("Content-ID") != "<"+LogoCID+">" {
		t.Fatal("HTML/Logo-Teile falsch")
	}
	_, _ = io.Copy(io.Discard, i)
}

func TestBuildMessagePlainWithoutHTML(t *testing.T) {
	from, _ := netmail.ParseAddress("k@example.de")
	to, _ := netmail.ParseAddress("a@example.de")
	msg, err := netmail.ReadMessage(strings.NewReader(string(buildMessage(from, to, Message{Subject: "x", Body: "text"}))))
	if err != nil || !strings.HasPrefix(msg.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("err=%v ct=%s", err, msg.Header.Get("Content-Type"))
	}
}
