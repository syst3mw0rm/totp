// Package totp implements the Time-Based One-Time Password Algorithm,
// specified in RFC 6238. It allows clients to implement Two-Factor
// Authentication, and interoperates with Google Authenticator.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// qrCodeData returns the data to be contained in a QR Code.
// label is the string that GA uses in the UI. secretkey should be this user's
// secret key. issuer is used to resolve conflicts.
// Reference - https://code.google.com/p/google-authenticator/wiki/ConflictingAccounts
// opt should be the configured Options for this TOTP. If a nil
// options is passed, then DefaultOptions is used.
func qrCodeData(label string, secretKey []byte, issuer string, opt *Options) string {
	if opt == nil {
		opt = DefaultOptions
	}

	// We need to URL Escape the label, but at the same time, spaces come through
	// as +'s, so we need to reverse that encoding...
	label = url.QueryEscape(label)
	label = strings.Replace(label, "+", " ", -1)

	secret := base32.StdEncoding.EncodeToString(secretKey)
	digits := strconv.Itoa(int(opt.Digits))
	period := strconv.Itoa(int(opt.TimeStep / time.Second))

	return fmt.Sprintf("otpauth://totp/%v?secret=%v&issuer=%v&Digits=%v&Period=%v", label, secret, issuer, digits, period)
}

// Return a URL to generate QRCode on Google Charts for use with authenticator apps.
func QRCodeGoogleChartsUrl(label string, secretKey []byte, issuer string, opt *Options, width int) string {
	data := url.QueryEscape(qrCodeData(label, secretKey, issuer, opt))
	return fmt.Sprintf("https://chart.googleapis.com/chart?cht=qr&chs=%vx%v&chl=%v", width, width, data)
}

// Options contains the different configurable values for a given TOTP
// invocation.
type Options struct {
	Time     func() time.Time
	Tries    []int64
	TimeStep time.Duration
	Digits   uint8
	Hash     func() hash.Hash
}

// DefaultOptions is pre-configured Options. It uses time.Now to get the
// current time, has a window size of 30 seconds, and tries the currently
// active window, and the previous one. It expects 6 digits, and uses sha1
// for its hash algorithm. These settings were chosen to be compatible with
// Google Authenticator.
var DefaultOptions = &Options{
	Time:     time.Now,
	Tries:    []int64{0, -1},
	TimeStep: 30 * time.Second,
	Digits:   6,
	Hash:     sha1.New,
}

var digit_power = []int64{
	1,          // 0
	10,         // 1
	100,        // 2
	1000,       // 3
	10000,      // 4
	100000,     // 5
	1000000,    // 6
	10000000,   // 7
	100000000,  // 8
	1000000000, // 9
}

// Authenticate verifies the TOTP userCode taking the key from secretKey and
// other options from o. If o is nil, then DefaultOptions is used instead.
func Authenticate(secretKey []byte, userCode string, o *Options) bool {
	if o == nil {
		o = DefaultOptions
	}

	if int(o.Digits) != len(userCode) {
		return false
	}

	uc, err := strconv.ParseInt(userCode, 10, 64)
	if err != nil {
		return false
	}

	t := o.Time().Unix() / int64(o.TimeStep/time.Second)
	var tbuf [8]byte

	hm := hmac.New(o.Hash, secretKey)
	var hashbuf []byte

	for i := 0; i < len(o.Tries); i++ {
		b := t + o.Tries[i]

		tbuf[0] = byte(b >> 56)
		tbuf[1] = byte(b >> 48)
		tbuf[2] = byte(b >> 40)
		tbuf[3] = byte(b >> 32)
		tbuf[4] = byte(b >> 24)
		tbuf[5] = byte(b >> 16)
		tbuf[6] = byte(b >> 8)
		tbuf[7] = byte(b)

		hm.Reset()
		hm.Write(tbuf[:])
		hashbuf = hm.Sum(hashbuf[:0])

		offset := hashbuf[len(hashbuf)-1] & 0xf
		truncatedHash := hashbuf[offset:]

		code := int64(truncatedHash[0])<<24 |
			int64(truncatedHash[1])<<16 |
			int64(truncatedHash[2])<<8 |
			int64(truncatedHash[3])

		code &= 0x7FFFFFFF
		code %= digit_power[len(userCode)]

		if code == uc {
			return true
		}
	}

	return false
}
