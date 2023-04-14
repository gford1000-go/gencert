package gencert

import (
	"crypto/tls"
	"os"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	ssl, err := NewDefaultCertificate("localhost", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := os.ReadFile(ssl["cert"])
	if err != nil {
		t.Fatal(err)
	}

	key, err := os.ReadFile(ssl["key"])
	if err != nil {
		t.Fatal(err)
	}

	_, err = tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
}
