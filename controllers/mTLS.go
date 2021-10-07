package controllers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os/exec"
	"time"
)

const (
	PRIVATE_KEY_SIZE = 2048
)

var (
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
	certDuration      = time.Hour * 24
	certRenewalWindow = time.Hour * 2 // roll the cert when we get within this window of expiring
)

func GetCertDuration() time.Duration {
	return certDuration
}

type MTLSCerts struct {
	caPEM            *bytes.Buffer
	caPrivKeyPEM     *bytes.Buffer
	certPEM          *bytes.Buffer
	certPrivKeyPEM   *bytes.Buffer
	clientPEM        *bytes.Buffer
	clientPrivKeyPEM *bytes.Buffer
	expiry           time.Time
}

func inCertRenewalWindow(expiry time.Time) bool {
	return time.Now().Add(certRenewalWindow).After(expiry)
}

func generateMTLSCerts(ns string) (*MTLSCerts, error) {
	// TODO(cdoan): handle the error, and put this into a function to reuse
	now := time.Now()
	expiry := now.Add(GetCertDuration())
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	ca := &x509.Certificate{
		// SerialNumber: big.NewInt(2019),
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Red Hat, Inc."},
			Country:      []string{"US"},
			CommonName:   getServiceName(ns),
		},
		NotBefore:             now,
		NotAfter:              expiry,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	// generate a private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, PRIVATE_KEY_SIZE)
	if err != nil {
		return nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	// convert to PEM
	caPEM, caPrivKeyPEM := PEMEncode(caBytes, caPrivKey)
	serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Red Hat, Inc."},
			Country:      []string{"US"},
			CommonName:   getServiceName(ns),
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    now,
		NotAfter:     expiry,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	cert.DNSNames = []string{getServiceName(ns)}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, PRIVATE_KEY_SIZE)
	if err != nil {
		return nil, err
	}

	// SIGN the cert/key with the previous CA
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	// convert the server cert/key to PEM Encoiding
	certPEM, certPrivKeyPEM := PEMEncode(certBytes, certPrivKey)

	// Client
	client := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Red Hat, Inc."},
			Country:      []string{"US"},
			CommonName:   getServiceName(ns),
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    now,
		NotAfter:     expiry,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		// ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, PRIVATE_KEY_SIZE)
	if err != nil {
		return nil, err
	}

	// SIGN the cert/key with the previous CA
	clientBytes, err := x509.CreateCertificate(rand.Reader, client, ca, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	// convert the server cert/key to PEM Encoiding
	clientPEM, clientPrivKeyPEM := PEMEncode(clientBytes, clientPrivKey)

	// fmt.Println("create ca:\n", ca)
	// fmt.Println("create ca privatekey:\n", caPrivKey)
	// fmt.Println("create ca cert:\n", caBytes)
	// fmt.Println("create ca cert in PEM format:\n", caPEM.String())
	// fmt.Println("create ca key in PEM format:\n", caPrivKeyPEM.String())

	// bufferToFile("ca.crt", caPEM.Bytes())

	// fmt.Println("create server certificate:\n", cert)
	// fmt.Println("create server key:\n", certPrivKey)

	// fmt.Println("sign cert:\n", certBytes)
	// fmt.Println("signed server cert in PEM:\n", certPEM)
	// fmt.Println("signed server key in PEM:\n", certPrivKeyPEM)

	// fmt.Println("signed client cert in PEM:\n", clientPEM)
	// fmt.Println("signed client key in PEM:\n", clientPrivKeyPEM)

	// bufferToFile("server.crt", certPEM.Bytes())
	// bufferToFile("server.key", certPrivKeyPEM.Bytes())
	// bufferToFile("client.crt", clientPEM.Bytes())
	// bufferToFile("client.key", clientPrivKeyPEM.Bytes())

	return &MTLSCerts{
		caPEM:            caPEM,
		caPrivKeyPEM:     caPrivKeyPEM,
		certPEM:          certPEM,
		certPrivKeyPEM:   certPrivKeyPEM,
		clientPEM:        clientPEM,
		clientPrivKeyPEM: clientPrivKeyPEM,
		expiry:           expiry,
	}, nil
}

func PEMEncode(caBytes []byte, caPrivKey *rsa.PrivateKey) (*bytes.Buffer, *bytes.Buffer) {
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return caPEM, caPrivKeyPEM
}

func bufferToFile(name string, thing []byte) {
	err := ioutil.WriteFile(name, thing, 0644)
	if err != nil {
		fmt.Println("failed to write file: " + name)
	}
}

func getServiceName(ns string) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", GRPC_SERVICE_NAME, ns)
}

func verifyCACert() error {
	out, err := exec.Command("openssl", "verify", "-CAfile", "ca.crt", "server.crt").Output()
	if err != nil {
		log.Fatal(err)
		return err
	}
	fmt.Printf("Output:\n%s\n", out)

	out, err = exec.Command("openssl", "verify", "-CAfile", "ca.crt", "client.crt").Output()
	if err != nil {
		log.Fatal(err)
		return err
	}
	fmt.Printf("Output:\n%s\n", out)
	return nil
}
