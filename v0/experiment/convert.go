package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	_ "crypto/x509"
	_ "unsafe"
)

//go:linkname processExtensions crypto/x509.processExtensions
func processExtensions(out *x509.Certificate) error

//go:linkname buildCertExtensions crypto/x509.buildCertExtensions
func buildCertExtensions(template *x509.Certificate, subjectIsEmpty bool, authorityKeyId []byte, subjectKeyId []byte) (ret []pkix.Extension, err error)

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionCRLNumber             = []int{2, 5, 29, 20}
	oidExtensionReasonCode            = []int{2, 5, 29, 21}
)

func combineExtensions(extensions []pkix.Extension, extraExtensions []pkix.Extension) ([]pkix.Extension, error) {
	extensionIds := map[string]struct{}{}
	allExtensions := []pkix.Extension{}

	for _, val := range extraExtensions {
		if _, ok := extensionIds[val.Id.String()]; ok {
			return nil, fmt.Errorf("duplicate extension %q", val.Id.String())
		}

		extensionIds[val.Id.String()] = struct{}{}
		allExtensions = append(allExtensions, val)
	}

	for _, val := range extensions {
		if _, ok := extensionIds[val.Id.String()]; ok {
			continue
		}

		extensionIds[val.Id.String()] = struct{}{}
		allExtensions = append(allExtensions, val)
	}

	return allExtensions, nil
}

func filterExtensions(extensions []pkix.Extension, without []asn1.ObjectIdentifier) []pkix.Extension {
	idsToBeRemoved := map[string]struct{}{}
	for _, val := range without {
		idsToBeRemoved[val.String()] = struct{}{}
	}

	filtered := make([]pkix.Extension, 0, len(extensions))
	for _, val := range extensions {
		if _, ok := idsToBeRemoved[val.Id.String()]; ok {
			continue
		}

		filtered = append(filtered, val)
	}

	return filtered
}

// *x509.CertificateRequest -> *x509.Certificate
// Populates the fields of a certificate from a certificate request.
// IMPORTANT: The following fields cannot be populated from a certificate request:
// - SerialNumber
// - SignatureAlgorithm
// - Signature
// - NotBefore
// - NotAfter
func CertificateRequestToCertificate(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	allExtensions, err := combineExtensions(csr.Extensions, csr.ExtraExtensions)
	if err != nil {
		return nil, err
	}

	cert := &x509.Certificate{
		// Version must be 3 according to RFC5280.
		// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.1
		Version: 3,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		Subject:        csr.Subject,
		RawSubject:     csr.RawSubject,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,

		Extensions: allExtensions,
	}

	if err := processExtensions(cert); err != nil {
		return nil, err
	}

	cert.ExtraExtensions = filterExtensions(cert.Extensions, []asn1.ObjectIdentifier{
		oidExtensionSubjectKeyId,
		oidExtensionKeyUsage,
		oidExtensionExtendedKeyUsage,
		oidExtensionAuthorityKeyId,
		oidExtensionBasicConstraints,
		oidExtensionSubjectAltName,
		oidExtensionCertificatePolicies,
		oidExtensionNameConstraints,
		oidExtensionCRLDistributionPoints,
		oidExtensionAuthorityInfoAccess,
		oidExtensionCRLNumber,
		oidExtensionReasonCode,
	})

	return cert, nil
}

func CertificateToCertificateRequest(cert *x509.Certificate) (*x509.CertificateRequest, error) {
	extraExtensions, err := buildCertExtensions(cert, false, nil, nil)
	if err != nil {
		return nil, err
	}

	allExtensions, err := combineExtensions(cert.Extensions, extraExtensions)
	if err != nil {
		return nil, err
	}

	cr := &x509.CertificateRequest{
		// Version 0 is the only one defined in the PKCS#10 standard, RFC2986.
		// This value isn't used by Go at the time of writing.
		// https://datatracker.ietf.org/doc/html/rfc2986#section-4
		Version: 0,

		PublicKeyAlgorithm: cert.PublicKeyAlgorithm,
		PublicKey:          cert.PublicKey,

		Subject:        cert.Subject,
		RawSubject:     cert.RawSubject,
		DNSNames:       cert.DNSNames,
		IPAddresses:    cert.IPAddresses,
		URIs:           cert.URIs,
		EmailAddresses: cert.EmailAddresses,

		Extensions: allExtensions,
	}

	cr.ExtraExtensions = filterExtensions(cr.Extensions, []asn1.ObjectIdentifier{
		oidExtensionSubjectAltName,
	})

	return cr, nil
}
