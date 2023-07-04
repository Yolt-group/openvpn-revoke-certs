package pinner

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"

	"github.com/pkg/errors"
)

const EnvVaultTLSServerName = "VAULT_TLS_SERVER_NAME"

var FailedPinError = errors.New("failed to verify public key")
var VerifyChainError = errors.New("failed to verify certificate chain")

func convertToDERs(publicKeysPEM []string) [][]byte {

	ders := make([][]byte, 0, len(publicKeysPEM))
	for _, pem := range publicKeysPEM {

		der, err := convertToDER(pem)
		if err != nil {
			panic("failed to convert public key from pem to der\n" + pem)
		}

		ders = append(ders, der)
	}

	return ders
}

func convertToDER(publicKeyPEM string) ([]byte, error) {

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode pem public key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse RSA public key")
	}

	keyRSA, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.Wrapf(err, "value returned from ParsePKIXPublicKey was not an RSA public key")
	}

	keyDER, err := x509.MarshalPKIXPublicKey(keyRSA)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal RSA public key for the second time")
	}

	return keyDER, nil
}

func newSecureTLSConfig(allowedRootCertsPEM []string) *tls.Config {

	cfg := &tls.Config{}

	cfg.RootCAs = x509.NewCertPool()
	for _, root := range allowedRootCertsPEM {
		if ok := cfg.RootCAs.AppendCertsFromPEM([]byte(root)); !ok {
			panic("failed to parse root certificate")
		}
	}

	// Use only modern ciphers
	cfg.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}

	// Use only TLS v1.2
	cfg.MinVersion = tls.VersionTLS12
	cfg.InsecureSkipVerify = false
	cfg.SessionTicketsDisabled = true

	// Support TLS SNI override
	if v := os.Getenv(EnvVaultTLSServerName); v != "" {
		cfg.ServerName = v
	}

	return cfg
}

func NewPinningDialer(pinnedPublicKeysPEMs []string, allowedRootCertsPEM []string) func(network, addr string) (net.Conn, error) {

	return func(network, addr string) (net.Conn, error) {

		cfg := newSecureTLSConfig(allowedRootCertsPEM)
		conn, err := tls.Dial(network, addr, cfg)
		if err != nil {
			return nil, err
		}

		chains := conn.ConnectionState().VerifiedChains
		if len(chains) != 1 {
			// Bail out for now (we could return a warning to client in future).
			return nil, VerifyChainError
		}

		peerCerts := conn.ConnectionState().PeerCertificates
		if len(chains[0]) != len(peerCerts) {
			// Bail out for now (we could return a warning to client in future).
			return nil, VerifyChainError
		}

		for _, key := range convertToDERs(pinnedPublicKeysPEMs) {

			for _, offeredCert := range chains[0] {

				offeredKey, err := x509.MarshalPKIXPublicKey(offeredCert.PublicKey)
				if err != nil {
					return nil, errors.Wrapf(err, "failed to mashal x509 public key")
				}

				if bytes.Compare(key, offeredKey) == 0 {
					return conn, nil
				}
			}
		}

		return nil, FailedPinError
	}
}
