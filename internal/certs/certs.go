package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// LoadOrCreate returns (certPath, keyPath, sha256Fingerprint).
//
// If both certFile and keyFile exist they are reused (stable fingerprint
// across restarts — good for pinning). Otherwise a fresh self-signed pair is
// generated and cached under ~/.snispf/.
func LoadOrCreate(certFile, keyFile, cn string) (string, string, string, error) {
	if cn == "" {
		cn = "SNISPF-HJ"
	}
	if certFile != "" && keyFile != "" {
		if cf, kf := fileExists(certFile), fileExists(keyFile); cf && kf {
			pemBytes, err := os.ReadFile(certFile)
			if err != nil {
				return "", "", "", err
			}
			fp, err := DERFingerprint(pemBytes)
			if err != nil {
				return "", "", "", err
			}
			return certFile, keyFile, fp, nil
		}
	}

	cacheDir, err := os.UserHomeDir()
	if err != nil {
		cacheDir = "."
	}
	cacheDir = filepath.Join(cacheDir, ".snispf")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", "", "", err
	}
	certPath := certFile
	if certPath == "" {
		certPath = filepath.Join(cacheDir, "snispf-cert.pem")
	}
	keyPath := keyFile
	if keyPath == "" {
		keyPath = filepath.Join(cacheDir, "snispf-key.pem")
	}

	if fileExists(certPath) && fileExists(keyPath) {
		pemBytes, err := os.ReadFile(certPath)
		if err != nil {
			return "", "", "", err
		}
		fp, err := DERFingerprint(pemBytes)
		if err != nil {
			return "", "", "", err
		}
		return certPath, keyPath, fp, nil
	}

	certPEM, keyPEM, err := GenerateSelfSigned(cn)
	if err != nil {
		return "", "", "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", "", err
	}
	log.Printf("Generated self-signed certificate -> %s", certPath)
	fp, err := DERFingerprint(certPEM)
	if err != nil {
		return "", "", "", err
	}
	return certPath, keyPath, fp, nil
}

// GenerateSelfSigned generates a (certPEM, keyPEM) pair with the same subject
// and extension profile as the Python backend: C=IR, O=SNISPF-HJ, CN=cn,
// CA:true, key usage digitalSignature|keyEncipherment|keyCertSign, SANs
// [cn, localhost, 127.0.0.1], validity 3650 days.
func GenerateSelfSigned(cn string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, nil, err
	}
	serial = new(big.Int).Or(serial, big.NewInt(1)) // force odd, 63-bit-ish
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Country:            []string{"IR"},
			Organization:       []string{"SNISPF-HJ"},
			CommonName:         cn,
			OrganizationalUnit: []string{},
		},
		NotBefore:             now,
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{cn, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

// DERFingerprint returns the SHA-256 (hex) of the DER certificate — the
// value to pin (pinnedPeerCertSha256).
func DERFingerprint(certPEM []byte) (string, error) {
	der, err := pemToDER(certPEM)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func pemToDER(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("certs: no PEM block found")
	}
	return block.Bytes, nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
