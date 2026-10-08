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
	Body    string
}

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
	var id [12]byte
	_, _ = rand.Read(id[:])
	domain := "localhost"
	if _, d, ok := strings.Cut(from.Address, "@"); ok {
		domain = d
	}
	h := []string{
		"From: " + from.String(),
		"To: " + to.Address,
		"Subject: " + mime.QEncoding.Encode("utf-8", m.Subject),
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <" + hex.EncodeToString(id[:]) + "@" + domain + ">",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: base64",
	}
	if m.ReplyTo != "" {
		h = append(h, "Reply-To: "+m.ReplyTo)
	}
	return []byte(strings.Join(h, "\r\n") + "\r\n\r\n" + wrap76(base64.StdEncoding.EncodeToString([]byte(m.Body))))
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
