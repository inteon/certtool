package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"

	_ "unsafe"
)

var (
	oidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	oidExtensionKeyUsage              = []int{2, 5, 29, 15}
	oidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	oidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	oidExtensionNameConstraints       = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	oidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	oidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	oidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	oidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

//go:linkname processExtensions crypto/x509.processExtensions
func processExtensions(out *x509.Certificate) error

//go:linkname buildCertExtensions crypto/x509.buildCertExtensions
func buildCertExtensions(template *x509.Certificate, subjectIsEmpty bool, authorityKeyId []byte, subjectKeyId []byte) (ret []pkix.Extension, err error)

func OverwriteFromExtensions(cert *x509.Certificate, extensions []pkix.Extension) {
	cert.Extensions = nil
	cert.ExtraExtensions = nil
	cert.UnhandledCriticalExtensions = nil

	for _, ext := range extensions {
		if canParseExtension(ext) {
			cert.Extensions = append(cert.Extensions, ext)
		} else {
			cert.ExtraExtensions = append(cert.ExtraExtensions, ext)
		}
	}

	processExtensions(cert)
}

func canParseExtension(ext pkix.Extension) bool {
	switch {
	case ext.Id.Equal(oidExtensionSubjectKeyId) ||
		ext.Id.Equal(oidExtensionKeyUsage) ||
		ext.Id.Equal(oidExtensionSubjectAltName) ||
		ext.Id.Equal(oidExtensionBasicConstraints) ||
		ext.Id.Equal(oidExtensionNameConstraints) ||
		ext.Id.Equal(oidExtensionCRLDistributionPoints) ||
		ext.Id.Equal(oidExtensionCertificatePolicies) ||
		ext.Id.Equal(oidExtensionAuthorityKeyId) ||
		ext.Id.Equal(oidExtensionExtendedKeyUsage) ||
		ext.Id.Equal(oidExtensionAuthorityInfoAccess):
		return true
	default:
		return false
	}
}

func CertificateToExtensions(cert *x509.Certificate) ([]pkix.Extension, error) {
	extensions, err := buildCertExtensions(cert, false, nil, nil)
	if err != nil {
		return nil, err
	}

	extensions = append(extensions, cert.Extensions...)

	return extensions, nil
}
