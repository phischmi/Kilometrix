package tokens

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"
)

// Approval ist ein signierter, zustandsloser Freigabe-Antrag: Wer ein Token beantragt,
// erzeugt einen solchen Antrag; der Admin gibt ihn per Link frei.
type Approval struct {
	Name  string `json:"n"`
	Email string `json:"e"`
	Exp   int64  `json:"x"` // Ablauf des Freigabe-Links (Unix-Sekunden)
}

// approvalDomain trennt die Signatur-Domäne: Ein Freigabe-Link darf nie als Zugangstoken
// durchgehen (und umgekehrt), obwohl beide mit demselben Secret signiert werden.
const approvalDomain = "approval:"

func signApproval(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(approvalDomain + body))
	return b64.EncodeToString(mac.Sum(nil))
}

// MintApproval erzeugt den signierten Freigabe-Antrag (body.signatur), gültig für ttl.
func MintApproval(secret, name, email string, ttl time.Duration) string {
	raw, _ := json.Marshal(Approval{Name: name, Email: email, Exp: time.Now().Add(ttl).Unix()})
	body := b64.EncodeToString(raw)
	return body + "." + signApproval(secret, body)
}

// VerifyApproval prüft Signatur und Ablauf eines Freigabe-Antrags.
func VerifyApproval(secret, v string) (Approval, error) {
	if secret == "" {
		return Approval{}, errors.New("AUTH_SECRET nicht gesetzt")
	}
	body, sig, ok := cutDot(v)
	if !ok {
		return Approval{}, errors.New("Freigabe-Link ungültig")
	}
	if !hmac.Equal([]byte(sig), []byte(signApproval(secret, body))) {
		return Approval{}, errors.New("Freigabe-Link ungültig")
	}
	raw, err := b64.DecodeString(body)
	if err != nil {
		return Approval{}, errors.New("Freigabe-Link ungültig")
	}
	var a Approval
	if err := json.Unmarshal(raw, &a); err != nil {
		return Approval{}, errors.New("Freigabe-Link ungültig")
	}
	if a.Exp < time.Now().Unix() {
		return Approval{}, errors.New("Freigabe-Link abgelaufen")
	}
	return a, nil
}

func cutDot(s string) (before, after string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}
