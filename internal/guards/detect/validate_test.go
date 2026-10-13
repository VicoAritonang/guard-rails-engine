package detect

import "testing"

// The validators exist to buy precision, so these tests are weighted towards
// the NEGATIVE cases: any 16-digit string passing as a card number is the
// failure that makes a PII guard unusable.

func TestLuhn(t *testing.T) {
	valid := []string{
		"4111111111111111",    // Visa test number
		"4111 1111 1111 1111", // with spaces
		"4111-1111-1111-1111", // with dashes
		"5425233430109903",    // Mastercard test number
		"374245455400126",     // Amex test number (15 digits)
		"6011111111111117",    // Discover test number
	}
	for _, s := range valid {
		if !Luhn(s) {
			t.Errorf("Luhn(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"4111111111111112",     // checksum off by one
		"8371049182730192",     // a plausible order number
		"1234567890123456",     // sequential
		"411111111111111a",     // non-digit
		"41111111111",          // too short
		"41111111111111111111", // too long
		"",
	}
	for _, s := range invalid {
		if Luhn(s) {
			t.Errorf("Luhn(%q) = true, want false", s)
		}
	}
}

// TestLuhnAloneIsNotEnough pins the reason the card rule layers three checks.
//
// All-zeroes satisfies the mod-10 checksum exactly (the digit sum is zero), so
// Luhn alone would accept the most common placeholder value in every test
// fixture on earth. The placeholder screens, not the checksum, are what reject
// it -- and that ordering is easy to undo by accident, so it is asserted here.
func TestLuhnAloneIsNotEnough(t *testing.T) {
	const placeholder = "0000000000000000"
	if !Luhn(placeholder) {
		t.Fatal("precondition changed: all-zeroes no longer satisfies Luhn")
	}
	if !IsRepeatedDigits(placeholder) {
		t.Error("all-zeroes must be caught by the repeated-digit screen")
	}
}

func TestCardBrand(t *testing.T) {
	cases := map[string]string{
		"4111111111111111": "visa",
		"5425233430109903": "mastercard",
		"374245455400126":  "amex",
		"6011111111111117": "discover",
		"9999999999999999": "unknown",
	}
	for card, want := range cases {
		if got := CardBrand(card); got != want {
			t.Errorf("CardBrand(%q) = %q, want %q", card, got, want)
		}
	}
}

func TestMod97IBAN(t *testing.T) {
	valid := []string{
		"DE89370400440532013000",
		"DE89 3704 0044 0532 0130 00",
		"GB82WEST12345698765432",
		"FR1420041010050500013M02606",
	}
	for _, s := range valid {
		if !Mod97(s) {
			t.Errorf("Mod97(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"DE89370400440532013001", // bad check digits
		"XX00INVALID",
		"DE89",
		"",
	}
	for _, s := range invalid {
		if Mod97(s) {
			t.Errorf("Mod97(%q) = true, want false", s)
		}
	}
}

func TestNIK(t *testing.T) {
	valid := []string{
		"3174051201900003", // Jakarta Selatan, male, born 12-01-1990
		"3174055201900003", // same, female (day + 40)
		"1101010101010001",
	}
	for _, s := range valid {
		if !NIK(s) {
			t.Errorf("NIK(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"8371049182730192",  // an order number: province 83 is valid but month 73 is not
		"0000000000000000",  // zero province
		"3174053201900003",  // day 32 after removing the female offset -> impossible
		"3174051213900003",  // month 13
		"3174053002900003",  // 30 February
		"3174051201900000",  // zero sequence
		"317405120190000",   // 15 digits
		"99740512019000031", // 17 digits
	}
	for _, s := range invalid {
		if NIK(s) {
			t.Errorf("NIK(%q) = true, want false", s)
		}
	}
}

func TestUSSSN(t *testing.T) {
	if !USSSN("536-90-4412") {
		t.Error("valid SSN rejected")
	}
	for _, s := range []string{
		"000-12-3456", // reserved area
		"666-12-3456", // reserved area
		"900-12-3456", // 9xx reserved
		"536-00-4412", // zero group
		"536-90-0000", // zero serial
		"123-45-6789", // the tutorial example
		"12-345-678",
	} {
		if USSSN(s) {
			t.Errorf("USSSN(%q) = true, want false", s)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	// A real key must score meaningfully higher than documentation filler,
	// because that gap is what the secrets guard thresholds on.
	realKey := "7Kq2mZv9RxTbNw4LpHsJdF6yQe1UoCiA3g"
	filler := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	example := "EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"

	if h := ShannonEntropy(realKey); h < 4.0 {
		t.Errorf("real key entropy %.2f is unexpectedly low", h)
	}
	if h := ShannonEntropy(filler); h > 0.1 {
		t.Errorf("repeated-character entropy %.2f should be ~0", h)
	}
	if ShannonEntropy(example) >= ShannonEntropy(realKey) {
		t.Error("documentation placeholder scored at least as high as a real key")
	}
	if ShannonEntropy("") != 0 {
		t.Error("empty string should score 0")
	}
}

func TestPlaceholderNumbers(t *testing.T) {
	if !IsRepeatedDigits("0000000000000000") {
		t.Error("repeated digits not detected")
	}
	if IsRepeatedDigits("4111111111111111") {
		t.Error("a real card was treated as repeated digits")
	}
	if !IsSequential("1234567890123456") {
		t.Error("ascending sequence not detected")
	}
	if !IsSequential("9876543210") {
		t.Error("descending sequence not detected")
	}
	if IsSequential("4111111111111111") {
		t.Error("a real card was treated as sequential")
	}
}

func TestNPWP(t *testing.T) {
	// 16-digit NPWP falls back to NIK validation (post-2024 scheme).
	if !NPWP("3174051201900003") {
		t.Error("NIK-based NPWP rejected")
	}
	if NPWP("12345") {
		t.Error("short string accepted as NPWP")
	}
}

func BenchmarkLuhn(b *testing.B) {
	for b.Loop() {
		_ = Luhn("4111 1111 1111 1111")
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	s := "7Kq2mZv9RxTbNw4LpHsJdF6yQe1UoCiA3g"
	for b.Loop() {
		_ = ShannonEntropy(s)
	}
}
