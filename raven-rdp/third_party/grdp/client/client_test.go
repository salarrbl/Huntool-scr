package client

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestClient(t *testing.T) {
	host := os.Getenv("RDP_TEST_HOST")
	if host == "" {
		t.Skip("set RDP_TEST_HOST to run this integration test")
	}
	user := os.Getenv("RDP_TEST_USER")
	pass := os.Getenv("RDP_TEST_PASS")
	if user == "" || pass == "" {
		t.Skip("set RDP_TEST_USER and RDP_TEST_PASS to run this integration test")
	}

	c := NewClient(host, user, pass, TC_RDP, nil)
	err := c.Login()
	if err != nil {
		fmt.Println("Login:", err)
	}
	c.OnReady(func() {
		fmt.Println("ready")
	})
	time.Sleep(10 * time.Second)
}
