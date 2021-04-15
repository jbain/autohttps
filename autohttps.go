package autohttps

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type Server struct {
	http.Server
	CertConfig CertConfig
}

func (srv *Server) ListenAndServe() error {
	// Generate self signed cert


	cert, key, err := generateCerts(NewCertConfig())
	if err != nil {
		fmt.Println(err)
		return err
	}

	go cleanupCerts(cert, key)
	err = srv.ListenAndServeTLS(cert, key)
	if err != nil {
		fmt.Println(err)
		return err
	}

	return nil
}

func cleanupCerts(cert, key string) {
	time.Sleep(5 * time.Second)

	err := os.Remove(cert)
	if err != nil {
		fmt.Print(err)
	}
	os.Remove(key)
	if err != nil {
		fmt.Print(err)
	}
}

type CertConfig struct {
	Host string
	ValidFrom time.Time
	ValidFor time.Duration
	IsCA bool
	RsaBits int
	EcdsaCurve string
	Ed25519Key bool
}

func NewCertConfig() CertConfig {
	return CertConfig{
		Host:      "localhost",
		ValidFrom:  time.Now(),
		ValidFor:   24 * 365 * time.Hour,
		IsCA:       false,
		RsaBits: 	4096,
		EcdsaCurve: "P256",
		Ed25519Key: false,
	}
}


func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func generateCerts(cfg CertConfig) (cert, key string, err error){

	certFile, err := ioutil.TempFile("./", "cert")
	keyFile, err := ioutil.TempFile("./", "key")

	cert = certFile.Name()
	key = keyFile.Name()

	if len(cfg.Host) == 0 {
		return cert, key, errors.New("Missing required --host parameter")
	}

	var priv interface{}

	switch cfg.EcdsaCurve {
	case "":
		if cfg.Ed25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else {
			priv, err = rsa.GenerateKey(rand.Reader, cfg.RsaBits)
		}
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		e := fmt.Sprintf("Unrecognized elliptic curve: %q", cfg.EcdsaCurve)
		return cert, key, errors.New(e)
	}
	if err != nil {
		e := fmt.Sprintf("Failed to generate private key: %v", err)
		return cert, key, errors.New(e)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	notAfter := cfg.ValidFrom.Add(cfg.ValidFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		e := fmt.Sprintf("Failed to generate serial number: %v", err)
		return cert, key, errors.New(e)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: cfg.ValidFrom,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(cfg.Host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if cfg.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		e := fmt.Sprintf("Failed to create certificate: %v", err)
		return cert, key, errors.New(e)
	}

	//certOut, err := os.Create("cert.pem")
	//if err != nil {
	//	e := fmt.Sprintf("Failed to open cert.pem for writing: %v", err)
	//	return cert, key, errors.New(e)
	//}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		e := fmt.Sprintf("Failed to write data to cert.pem: %v", err)
		return cert, key, errors.New(e)
	}
	if err := certFile.Close(); err != nil {
		e := fmt.Sprintf("Error closing cert.pem: %v", err)
		return cert, key, errors.New(e)
	}
	log.Printf("wrote %s\n", cert)

	//keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	//if err != nil {
	//	e := fmt.Sprintf("Failed to open key.pem for writing: %v", err)
	//	return cert, key, errors.New(e)
	//}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		e := fmt.Sprintf("Unable to marshal private key: %v", err)
		return cert, key, errors.New(e)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		e := fmt.Sprintf("Failed to write data to key.pem: %v", err)
		return cert, key, errors.New(e)
	}
	if err := keyFile.Close(); err != nil {
		e := fmt.Sprintf("Error closing key.pem: %v", err)
		return cert, key, errors.New(e)
	}
	log.Printf("wrote %s\n", key)

	return cert, key, nil
}
