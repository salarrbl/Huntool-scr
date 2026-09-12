package nla

import (
	"testing"
)

func TestEncodeDERTRequest(t *testing.T) {
	ntlm := NewNTLMv2("", "", "")
	msg := ntlm.GetNegotiateMessage()
	result := EncodeDERTRequest([]Message{msg}, nil, nil)
	if len(result) == 0 {
		t.Error("expected non-empty encoded request")
	}
}
