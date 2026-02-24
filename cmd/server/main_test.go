package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"safe_web/internal/store"
)

func TestEnrollTokenSingleUseAndTTL(t *testing.T) {
	mem := store.NewMemoryStore()
	client, err := mem.CreateClient("device", time.Now())
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	tokenValue, tokenHash := generateToken()
	_ = tokenValue

	token := store.EnrollToken{
		TokenHash: tokenHash,
		ClientID:  client.ID,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}
	if _, err := mem.CreateEnrollToken(token); err != nil {
		t.Fatalf("create token: %v", err)
	}

	if _, err := mem.ConsumeEnrollToken(tokenHash, time.Now()); err != nil {
		t.Fatalf("consume token first time: %v", err)
	}
	if _, err := mem.ConsumeEnrollToken(tokenHash, time.Now()); err == nil {
		t.Fatalf("expected token to be single-use")
	}

	expiredHash := hashToken("expired")
	expired := store.EnrollToken{
		TokenHash: expiredHash,
		ClientID:  client.ID,
		ExpiresAt: time.Now().Add(-1 * time.Minute),
		CreatedAt: time.Now(),
	}
	if _, err := mem.CreateEnrollToken(expired); err != nil {
		t.Fatalf("create expired token: %v", err)
	}
	if _, err := mem.ConsumeEnrollToken(expiredHash, time.Now()); err == nil {
		t.Fatalf("expected expired token to fail")
	}
}

func TestMTLSHandshake(t *testing.T) {
	caCert, caKey := createCA(t)
	clientCert, clientKey := createClientCert(t, caCert, caKey)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caPool,
	}
	server.StartTLS()
	defer server.Close()

	clientTLS := &tls.Config{
		RootCAs:      caPool,
		Certificates: []tls.Certificate{{Certificate: [][]byte{clientCert.Raw}, PrivateKey: clientKey}},
	}
	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig = clientTLS

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("mtls request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func createCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, key
}

func createClientCert(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	return cert, key
}

func TestCSRParsing(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}

	req := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "client"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	parsed, err := parseCSR(string(csrPEM))
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := validateCSR(parsed); err != nil {
		t.Fatalf("validate csr: %v", err)
	}
}
