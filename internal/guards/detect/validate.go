// Package detect holds the value validators shared by the PII, secrets and
// leak guards.
//
// These exist to solve the single biggest practical problem with regex-based
// PII detection: precision. The regex for a credit card matches any 16 digits,
// which means every order number, tracking code and timestamp in a support
// transcript becomes a "card number". Running the actual checksum turns a
// detector with ~30% precision into one with ~99% precision, at a cost of a
// few nanoseconds per candidate -- and precision is what decides whether an
// operator leaves the guardrail switched on.
package detect

import (
	"math"
	"strings"
	"time"
)

// Luhn validates the mod-10 checksum used by payment cards.
func Luhn(s string) bool {
	sum, digits, alt := 0, 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		digits++
		alt = !alt
	}
	return digits >= 12 && digits <= 19 && sum%10 == 0
}

// CardBrand identifies the issuer from the IIN prefix. Reporting the brand
// rather than the number lets an audit log stay useful without being sensitive.
func CardBrand(s string) string {
	d := onlyDigits(s)
	switch {
	case strings.HasPrefix(d, "4"):
		return "visa"
	case len(d) >= 2 && d[:2] >= "51" && d[:2] <= "55":
		return "mastercard"
	case len(d) >= 4 && d[:4] >= "2221" && d[:4] <= "2720":
		return "mastercard"
	case len(d) >= 2 && (d[:2] == "34" || d[:2] == "37"):
		return "amex"
	case strings.HasPrefix(d, "6011"), strings.HasPrefix(d, "65"):
		return "discover"
	case len(d) >= 2 && d[:2] >= "35" && d[:2] <= "35":
		return "jcb"
	}
	return "unknown"
}

// Mod97 validates an IBAN using the ISO 7064 mod-97 check.
func Mod97(iban string) bool {
	s := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(iban))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	// Move the first four characters to the end, then expand letters to digits.
	rearranged := s[4:] + s[:4]
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		switch {
		case c >= '0' && c <= '9':
			rem = rem*10 + int(c-'0')
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			rem = rem*100 + v
		default:
			return false
		}
		rem %= 97
	}
	return rem == 1
}

// NIK validates an Indonesian national identity number.
//
// The format is PPKKSSDDMMYYNNNN: province, regency, district, then a birth
// date where women have 40 added to the day field, then a sequence number.
// Checking the embedded date is what separates a real NIK from any other
// 16-digit string, and it matters here because Indonesian support transcripts
// are full of 16-digit order references.
func NIK(s string) bool {
	d := onlyDigits(s)
	if len(d) != 16 {
		return false
	}
	province := atoi(d[0:2])
	if province < 11 || province > 96 {
		return false
	}
	if atoi(d[2:4]) == 0 || atoi(d[4:6]) == 0 {
		return false
	}

	day := atoi(d[6:8])
	if day > 40 { // female marker
		day -= 40
	}
	month := atoi(d[8:10])
	if day < 1 || day > 31 || month < 1 || month > 12 {
		return false
	}
	// Reject impossible dates such as 31 February.
	yy := atoi(d[10:12])
	year := 1900 + yy
	if year > time.Now().Year() {
		year = 2000 + yy
	}
	t := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	if t.Day() != day || int(t.Month()) != month {
		return false
	}
	// The trailing sequence is never all zeroes on an issued card.
	return atoi(d[12:16]) != 0
}

// NPWP validates an Indonesian tax number (15 digits, mod-11 style check on
// the first eight digits).
func NPWP(s string) bool {
	d := onlyDigits(s)
	if len(d) != 15 && len(d) != 16 {
		return false
	}
	if len(d) == 16 { // NIK-based NPWP since 2024
		return NIK(d)
	}
	weights := []int{3, 2, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i, w := range weights {
		sum += int(d[i]-'0') * w
	}
	check := 11 - sum%11
	if check >= 10 {
		check -= 10
	}
	return check == int(d[8]-'0')
}

// USSSN rejects the reserved ranges that make up most false positives.
func USSSN(s string) bool {
	d := onlyDigits(s)
	if len(d) != 9 {
		return false
	}
	area, group, serial := d[0:3], d[3:5], d[5:9]
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	// 123-45-6789 is the canonical example in every tutorial on earth.
	return d != "123456789"
}

// ShannonEntropy returns bits per character. High-entropy strings are the
// signature of a real credential; low-entropy ones are English prose that
// happened to match a key-shaped regex.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func onlyDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// OnlyDigits is exported for guards that need the normalized numeric form.
func OnlyDigits(s string) string { return onlyDigits(s) }

// IsRepeatedDigits catches placeholder values like 0000000000000000 and
// 1111111111111111, which pass Luhn surprisingly often but are never real.
func IsRepeatedDigits(s string) bool {
	d := onlyDigits(s)
	if len(d) < 4 {
		return false
	}
	for i := 1; i < len(d); i++ {
		if d[i] != d[0] {
			return false
		}
	}
	return true
}

// IsSequential catches 1234567890123456 style test data.
func IsSequential(s string) bool {
	d := onlyDigits(s)
	if len(d) < 6 {
		return false
	}
	asc, desc := true, true
	for i := 1; i < len(d); i++ {
		if (int(d[i])-int(d[i-1])+10)%10 != 1 {
			asc = false
		}
		if (int(d[i-1])-int(d[i])+10)%10 != 1 {
			desc = false
		}
	}
	return asc || desc
}
