package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type totpParams struct {
	secret []byte
	digits int
	period int
	algo   func() hash.Hash
}

// parseOTP accepts a bare base32 secret or an otpauth://totp/... URI.
func parseOTP(s string) (*totpParams, error) {
	p := &totpParams{digits: 6, period: 30, algo: sha1.New}
	secret := s
	if strings.HasPrefix(s, "otpauth://") {
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("invalid otpauth URI: %w", err)
		}
		if u.Host != "totp" {
			return nil, fmt.Errorf("unsupported otpauth type %q (only totp)", u.Host)
		}
		q := u.Query()
		secret = q.Get("secret")
		if v := q.Get("digits"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 6 || n > 8 {
				return nil, fmt.Errorf("invalid digits %q", v)
			}
			p.digits = n
		}
		if v := q.Get("period"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("invalid period %q", v)
			}
			p.period = n
		}
		switch strings.ToUpper(q.Get("algorithm")) {
		case "", "SHA1":
		case "SHA256":
			p.algo = sha256.New
		case "SHA512":
			p.algo = sha512.New
		default:
			return nil, fmt.Errorf("unsupported algorithm %q", q.Get("algorithm"))
		}
	}
	secret = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("invalid base32 secret")
	}
	p.secret = key
	return p, nil
}

// code returns the RFC 6238 code at t and the seconds until it rolls over.
func (p *totpParams) code(t time.Time) (string, int) {
	counter := uint64(t.Unix()) / uint64(p.period)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(p.algo, p.secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < p.digits; i++ {
		mod *= 10
	}
	remaining := p.period - int(t.Unix()%int64(p.period))
	return fmt.Sprintf("%0*d", p.digits, bin%mod), remaining
}
