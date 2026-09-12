package nla

import (
	"testing"
)

func TestNewNTLMv2(t *testing.T) {
	ntlm := NewNTLMv2("DOMAIN", "user", "pass")
	if ntlm == nil {
		t.Fatal("expected non-nil NTLMv2")
	}
}

func TestGetNegotiateMessage(t *testing.T) {
	ntlm := NewNTLMv2("", "user", "pass")
	msg := ntlm.GetNegotiateMessage()
	if msg == nil {
		t.Fatal("expected non-nil NegotiateMessage")
	}
}
