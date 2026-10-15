package main

import "crypto/x509"

func x509ParseFirst(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}
