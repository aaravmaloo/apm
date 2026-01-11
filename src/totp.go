package apm

import (
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

func GenerateTOTP(secret string) (string, error) {
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.ToUpper(secret)
	return totp.GenerateCode(secret, time.Now())
}

func TimeRemaining() int {
	return 30 - (int(time.Now().Unix()) % 30)
}