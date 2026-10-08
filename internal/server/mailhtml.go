package server

import (
	"bytes"
	_ "embed" // für logo.png
	"html/template"

	"github.com/phischmi/kilometrix/internal/mail"
)

//go:embed logo.png
var logoPNG []byte

// mailView beschreibt eine Mail im einheitlichen Layout (Logo, Text, Daten, Button, Code).
type mailView struct {
	Title   string
	Intro   string
	Rows    [][2]string // Label/Wert-Paare (z. B. Name, Mail)
	Code    string      // z. B. das Token (Monospace-Kasten)
	Steps   []string
	Button  string // Beschriftung; leer = kein Button
	URL     string
	Note    string
	LogoSrc template.URL // cid:… — template.URL, sonst ersetzt html/template das cid:-Schema
}

var mailTmpl = template.Must(template.New("mail").Parse(`<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:24px 12px;background:#f6f7f9;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1b1f24;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border:1px solid #d5d9e0;border-radius:12px;">
<tr><td style="padding:24px 28px 8px 28px;">
  <img src="{{.LogoSrc}}" width="48" height="48" alt="Kilometrix" style="display:block;border:0;margin-bottom:24px;">
  <h1 style="margin:0 0 12px 0;font-size:20px;line-height:1.3;">{{.Title}}</h1>
  <p style="margin:0 0 16px 0;font-size:15px;line-height:1.5;">{{.Intro}}</p>
{{if .Rows}}  <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 16px 0;font-size:15px;">
{{range .Rows}}    <tr><td style="padding:2px 16px 2px 0;color:#667085;">{{index . 0}}</td><td style="padding:2px 0;font-weight:600;">{{index . 1}}</td></tr>
{{end}}  </table>
{{end}}{{if .Code}}  <p style="margin:0 0 16px 0;padding:12px;background:#f1f3f6;border:1px solid #d5d9e0;border-radius:8px;font-family:Consolas,Menlo,monospace;font-size:13px;line-height:1.4;word-break:break-all;">{{.Code}}</p>
{{end}}{{if .Steps}}  <ol style="margin:0 0 16px 0;padding-left:20px;font-size:15px;line-height:1.5;">
{{range .Steps}}    <li>{{.}}</li>
{{end}}  </ol>
{{end}}{{if .Button}}  <p style="margin:0 0 8px 0;"><a href="{{.URL}}" style="display:inline-block;padding:12px 22px;background:#0b5fff;color:#ffffff;text-decoration:none;border-radius:8px;font-size:15px;font-weight:600;">{{.Button}}</a></p>
  <p style="margin:0 0 16px 0;font-size:12px;color:#667085;word-break:break-all;">Falls der Button nicht funktioniert: <a href="{{.URL}}" style="color:#0b5fff;">{{.URL}}</a></p>
{{end}}{{if .Note}}  <p style="margin:0 0 8px 0;font-size:13px;color:#667085;line-height:1.5;">{{.Note}}</p>
{{end}}</td></tr>
<tr><td style="padding:12px 28px 20px 28px;font-size:12px;color:#98a2b3;">Kilometrix · Straßenkilometer für Excel</td></tr>
</table></td></tr></table></body></html>`))

// withHTML ergänzt eine Mail um die HTML-Fassung mit eingebettetem Logo.
func withHTML(m mail.Message, v mailView) mail.Message {
	v.LogoSrc = template.URL("cid:" + mail.LogoCID)
	var b bytes.Buffer
	if err := mailTmpl.Execute(&b, v); err != nil {
		return m // Text-Fassung genügt als Rückfall
	}
	m.HTML = b.String()
	m.Logo = logoPNG
	return m
}
