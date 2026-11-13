package core

import (
	"strings"
	"testing"
)

var vaultSecret = []byte("vault-test-secret-key")

func TestVaultSealRoundTrip(t *testing.T) {
	v := NewVault(vaultSecret)
	ph := v.Mask("email", "andi@nusantara.co.id")

	token, err := v.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(token, "andi") {
		t.Fatal("the token must not carry the value in the clear")
	}

	restored := NewVault(vaultSecret)
	if err := restored.Unseal(token); err != nil {
		t.Fatal(err)
	}
	if out, n := restored.Restore("sent to " + ph); n != 1 || out != "sent to andi@nusantara.co.id" {
		t.Errorf("Restore = %q, %d", out, n)
	}
}

func TestVaultUnsealRefusesForeignTokens(t *testing.T) {
	v := NewVault(vaultSecret)
	v.Mask("email", "andi@nusantara.co.id")
	token, err := v.Seal()
	if err != nil {
		t.Fatal(err)
	}

	if err := NewVault([]byte("a-different-secret-key")).Unseal(token); err == nil {
		t.Error("a token sealed under another secret must not open")
	}
	tampered := token[:len(token)-2] + "AA"
	if err := NewVault(vaultSecret).Unseal(tampered); err == nil {
		t.Error("a tampered token must not open")
	}
	if err := NewVault(vaultSecret).Unseal("not a token"); err == nil {
		t.Error("garbage must not open")
	}
}

func TestEmptyVaultSealsToNothing(t *testing.T) {
	token, err := NewVault(vaultSecret).Seal()
	if err != nil || token != "" {
		t.Errorf("Seal = %q, %v", token, err)
	}
}
