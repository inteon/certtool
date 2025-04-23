package internal

import (
	"bytes"
	"crypto/x509"
	"net"
	"net/url"
	"testing"
)

func TestUnmarshal(t *testing.T) {
	urlValue, err := url.Parse("tresorit://example.com")
	if err != nil {
		t.Fatal(err)
	}

	cert := x509.Certificate{
		DNSNames:       []string{"example.com", "example.org"},
		EmailAddresses: []string{"test@goog.com"},
		IPAddresses: []net.IP{
			net.ParseIP("1.13.1.1"),
		},
		URIs: []*url.URL{urlValue},
	}

	extensions, err := CertificateToExtensions(&cert)
	if err != nil {
		t.Fatal(err)
	}

	var sanValue []byte
	for _, extension := range extensions {
		if extension.Id.Equal(oidExtensionSubjectAltName) {
			sanValue = extension.Value
		}
	}

	generalNames, err := UnmarshallGeneralNames(sanValue)
	if err != nil {
		t.Fatal(err)
	}

	if generalNames.DNSNames[0] != cert.DNSNames[0] {
		t.Fatalf("Expected %v, got %v", generalNames.DNSNames[0], cert.DNSNames[0])
	}

	if generalNames.DNSNames[1] != cert.DNSNames[1] {
		t.Fatalf("Expected %v, got %v", generalNames.DNSNames[1], cert.DNSNames[1])
	}

	if generalNames.RFC822Names[0] != cert.EmailAddresses[0] {
		t.Fatalf("Expected %v, got %v", generalNames.RFC822Names[0], cert.EmailAddresses[0])
	}
}

func TestMarshal(t *testing.T) {
	cert := x509.Certificate{
		DNSNames: []string{"example.com"},
	}

	extensions, err := CertificateToExtensions(&cert)
	if err != nil {
		t.Fatal(err)
	}

	var sanValue []byte
	for _, extension := range extensions {
		if extension.Id.Equal(oidExtensionSubjectAltName) {
			sanValue = extension.Value
		}
	}

	resultValue, err := MarshallGeneralNames(
		GeneralNames{
			DNSNames: cert.DNSNames,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sanValue, resultValue) {
		t.Fatalf("Expected %v, got %v", sanValue, resultValue)
	}
}
