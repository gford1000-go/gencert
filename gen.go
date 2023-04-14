package gencert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

var defaultBits = 4096

type Encoder func([]byte) []byte

func pemKeyEncode(key []byte) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: key,
		})
}

func pemCertEncode(key []byte) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: key,
		})
}

// SelfSignedCert is a key/cert pair created by an instance of SelfSignedCertGenerator
type SelfSignedCert struct {
	Cert    []byte
	Expires time.Time
	Key     []byte
}

// String returns the cert only
func (s *SelfSignedCert) String() string {
	return fmt.Sprint(string(s.Cert))
}

// SaveTempFiles writes the key and certificate to temporary files
// Left to caller to clear away the files after use
func (s *SelfSignedCert) SaveTempFiles() (string, string, error) {
	cf, err := s.saveFile("cert", "tmp", s.Cert)
	if err != nil {
		return "", "", err
	}
	kf, err := s.saveFile("key", "tmp", s.Key)
	if err != nil {
		return "", "", err
	}
	return kf, cf, nil
}

func (s *SelfSignedCert) saveFile(prefix, ext string, b []byte) (string, error) {
	f, err := os.CreateTemp("", fmt.Sprintf("%s*.%s", prefix, ext))
	if err != nil {
		return "", err
	}
	defer f.Close()

	_, err = f.Write(b)
	if err != nil {
		return "", err
	}

	return f.Name(), nil
}

// SelfSignedCertGenerator provides flexibility in certificate generation
type SelfSignedCertGenerator struct {
	Bits        int     // The length of the private key - defaults to 4096
	CertEncoder Encoder // The encoder for Certificate - defaults to PEM
	KeyEncoder  Encoder // The encoder for Key - defaults to PEM
}

// Create generates a SelfSignedCert for the common name and lifetime
func (s *SelfSignedCertGenerator) Create(commonName string, ttl time.Duration) (*SelfSignedCert, error) {
	s.applyDefaults()
	return s.createCertAndKey(commonName, ttl)
}

func (s *SelfSignedCertGenerator) applyDefaults() {
	if s.Bits == 0 {
		s.Bits = defaultBits
	}
	if s.CertEncoder == nil {
		s.CertEncoder = pemCertEncode
	}
	if s.KeyEncoder == nil {
		s.KeyEncoder = pemKeyEncode
	}
}

func (s *SelfSignedCertGenerator) createCertAndKey(commonName string, ttl time.Duration) (*SelfSignedCert, error) {
	// Create key pair
	key, err := rsa.GenerateKey(rand.Reader, s.Bits)
	if err != nil {
		return nil, err
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(ttl)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber:          big.NewInt(0),
		DNSNames:              []string{commonName},
		Subject:               pkix.Name{CommonName: commonName},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	// Create self-signed certificate using template
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return &SelfSignedCert{
		Expires: notAfter,
		Key:     s.KeyEncoder(keyBytes),
		Cert:    s.CertEncoder(certBytes),
	}, nil
}

// NewDefaultCertificate creates a self-signed certificate and key and saves
// them to temporary files whose names are returned, using default values.
//
//	Key for certificate: "cert"
//	Key for private key: "key"
func NewDefaultCertificate(commonName string, ttl time.Duration) (map[string]string, error) {
	// Create, save and return cert and key files, where
	// the certificate has been uniquely generated at startup
	g := &SelfSignedCertGenerator{}
	s, err := g.Create(commonName, ttl)
	if err != nil {
		return nil, err
	}

	kf, cf, err := s.SaveTempFiles()
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"cert": cf,
		"key":  kf,
	}, nil
}
