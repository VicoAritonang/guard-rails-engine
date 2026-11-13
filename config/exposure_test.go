package config

import "testing"

func TestCheckExposure(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{"open gateway with a provider", Config{Addr: ":8080", Provider: "openai"}, false},
		{"mock provider holding a real key", Config{Addr: ":8080", Provider: "mock", GroqAPIKey: "k"}, false},
		{"mock provider and no upstream", Config{Addr: ":8080", Provider: "mock"}, true},
		{"api keys set", Config{Addr: ":8080", Provider: "openai", APIKeys: []string{"k"}}, true},
		{"loopback", Config{Addr: "127.0.0.1:8080", Provider: "openai"}, true},
		{"ipv6 loopback", Config{Addr: "[::1]:8080", Provider: "openai"}, true},
		{"localhost", Config{Addr: "localhost:8080", Provider: "openai"}, true},
		{"explicit dev opt-in", Config{Addr: ":8080", Provider: "openai", InsecureDev: true}, true},
		{
			"published secret on the network",
			Config{Addr: ":8080", Provider: "openai", APIKeys: []string{"k"}, Secret: []byte("local-dev-secret-key-32chars")},
			false,
		},
		{
			"published secret on loopback",
			Config{Addr: "127.0.0.1:8080", Provider: "openai", Secret: []byte("change-me-to-a-long-random-string")},
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.CheckExposure()
			if c.ok && err != nil {
				t.Errorf("unexpected refusal: %v", err)
			}
			if !c.ok && err == nil {
				t.Error("expected a refusal")
			}
		})
	}
}
