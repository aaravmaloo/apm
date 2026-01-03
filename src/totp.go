package apm

import (
	"time"

	"github.com/pquerna/otp/totp"
)

func GenerateTOTP(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}

func TimeRemaining() int {
	return 30 - (int(time.Now().Unix()) % 30)
}
