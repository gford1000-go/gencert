[![Go Doc](https://pkg.go.dev/badge/github.com/gford1000-go/x509.svg)](https://pkg.go.dev/github.com/gford1000-go/x509)
[![Go Report Card](https://goreportcard.com/badge/github.com/gford1000-go/x509)](https://goreportcard.com/report/github.com/gford1000-go/x509)

gencert
=======

gencert provides a simple mechanism to create self-signed x509 certificates.

## Use

For default settings, call `NewDefaultCertificate`, which will return a map containing the location of the temporary files storing the new certificate and key using PEM encoding.

For more granular behaviour, use `SelfSignedCertGenerator`.


```go
func main() {
	// Basic information needed for the certificate creation
	commonName := flag.String("n", "localhost", "Common name for certificate")
	timeout := flag.Int("t", 10, "Hours to certificate expiry")
	flag.Parse()

	// Create a self-signed certificate for TLS
	ssl, err := NewDefaultCertificate(*commonName, time.Duration(*timeout)*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	// As the certificate is self-signed, it needs to be added to clients
	// This log allows the certificate location to be found
	log.Printf("Certificate saved to: %s\n", ssl["cert"])

	// Set up server
	mux := http.NewServeMux()
	// add handers ...

	// Start server
	log.Fatal(http.ListenAndServeTLS(":443", ssl["cert"], ssl["key"], mux))
}
```

## How?

This command line is all you need.

```
go get github.com/gford1000-go/x509
```
