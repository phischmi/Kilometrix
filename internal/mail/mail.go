// Package mail versendet einfache Textmails über einen SMTP-Relay (z. B. Brevo, Port 587
// mit STARTTLS) — nur stdlib.
package mail

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Message ist eine Textmail. Alle Adress- und Betrefffelder werden vor dem Versand auf
// Zeilenumbrüche geprüft (Schutz vor Header-Injection).
type Message struct {
	To      string
	ReplyTo string // optional
	Subject string
	Body    string // Text-Fassung (immer nötig; Fallback für reine Text-Clients)
	HTML    string // optional: HTML-Fassung; verweist ggf. per cid:LogoCID auf Logo
	Logo    []byte // optional: PNG, wird als Inline-Bild mit Content-ID LogoCID eingebettet
}

// LogoCID ist die Content-ID des eingebetteten Logos (im HTML als src="cid:logo@kilometrix").
const LogoCID = "logo@kilometrix"

// Sender versendet Mails. Hinter dem Interface lässt sich der Versand in Tests ersetzen.
type Sender interface {
	Send(Message) error
}

// SMTP ist der echte Versand über einen SMTP-Relay.
type SMTP struct {
	Host, Port, User, Pass string
	From                   string // Absenderadresse, z. B. kilometrix@example.de
}

// Send baut die Mail und sendet sie. net/smtp nutzt STARTTLS automatisch, wenn der Server
// es anbietet (Port 587); AUTH PLAIN wird von net/smtp nur über TLS bzw. localhost erlaubt.
func (s SMTP) Send(m Message) error {
	for _, v := range []string{m.To, m.ReplyTo, m.Subject, s.From} {
		if strings.ContainsAny(v, "\r\n") {
			return errors.New("ungültige Zeichen in Mail-Header")
		}
	}
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return fmt.Errorf("Absender ungültig: %w", err)
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return fmt.Errorf("Empfänger ungültig: %w", err)
	}
	msg := buildMessage(from, to, m)

	addr := net.JoinHostPort(s.Host, s.Port)
	var auth smtp.Auth
	if s.User != "" {
		auth = smtp.PlainAuth("", s.User, s.Pass, s.Host)
	}
	return smtp.SendMail(addr, auth, from.Address, []string{to.Address}, msg)
}

func buildMessage(from, to *mail.Address, m Message) []byte {
	domain := "localhost"
	if _, d, ok := strings.Cut(from.Address, "@"); ok {
		domain = d
	}
	h := []string{
		"From: " + from.String(),
		"To: " + to.Address,
		"Subject: " + mime.QEncoding.Encode("utf-8", m.Subject),
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <" + randHex(12) + "@" + domain + ">",
		"MIME-Version: 1.0",
	}
	if m.ReplyTo != "" {
		h = append(h, "Reply-To: "+m.ReplyTo)
	}
	text := "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		wrap76(base64.StdEncoding.EncodeToString([]byte(m.Body)))
	if m.HTML == "" {
		return []byte(strings.Join(h, "\r\n") + "\r\n" + text)
	}

	// multipart/alternative: Text zuerst, dann (HTML [+ Logo]) — Clients zeigen den letzten verständlichen Teil.
	alt, rel := "alt_"+randHex(8), "rel_"+randHex(8)
	html := "Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		wrap76(base64.StdEncoding.EncodeToString([]byte(m.HTML)))
	var b strings.Builder
	b.WriteString(strings.Join(h, "\r\n") + "\r\nContent-Type: multipart/alternative; boundary=\"" + alt + "\"\r\n\r\n")
	b.WriteString("--" + alt + "\r\n" + text + "\r\n")
	if len(m.Logo) == 0 {
		b.WriteString("--" + alt + "\r\n" + html + "\r\n")
	} else {
		b.WriteString("--" + alt + "\r\nContent-Type: multipart/related; boundary=\"" + rel + "\"\r\n\r\n")
		b.WriteString("--" + rel + "\r\n" + html + "\r\n")
		b.WriteString("--" + rel + "\r\nContent-Type: image/png; name=\"logo.png\"\r\nContent-Transfer-Encoding: base64\r\n" +
			"Content-ID: <" + LogoCID + ">\r\nContent-Disposition: inline; filename=\"logo.png\"\r\n\r\n" +
			wrap76(base64.StdEncoding.EncodeToString(m.Logo)) + "\r\n")
		b.WriteString("--" + rel + "--\r\n")
	}
	b.WriteString("--" + alt + "--\r\n")
	return []byte(b.String())
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// wrap76 bricht base64 in 76-Zeichen-Zeilen um (RFC 2045).
func wrap76(s string) string {
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76] + "\r\n")
		s = s[76:]
	}
	b.WriteString(s + "\r\n")
	return b.String()
}
