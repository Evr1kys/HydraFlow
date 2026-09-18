package smartsub

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// SubscriptionToken derives a user-scoped credential without exposing the admin
// secret. Rotating the admin secret revokes all issued subscription links.
func SubscriptionToken(secret, email string) string {
	if secret == "" || email == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("hydraflow/subscription/v1\x00" + email))
	return hex.EncodeToString(mac.Sum(nil))
}

func validSubscriptionToken(secret, email, token string) bool {
	expected := SubscriptionToken(secret, email)
	return expected != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(token)) == 1
}
