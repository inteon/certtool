package parse

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"

	"playground/parse/gen"
)

func FromCertificateRequest(csr *x509.CertificateRequest) *gen.CertificateSigningRequest {
	tmpl := x509.Certificate{}
	tmpl.RawSubject = csr.RawSubject
	tmpl.Subject = csr.Subject

	allExtensions := make([]pkix.Extension, 0, len(csr.Extensions)+len(csr.ExtraExtensions))
	allExtensions = append(allExtensions, csr.Extensions...)
	allExtensions = append(allExtensions, csr.ExtraExtensions...)

	OverwriteFromExtensions(&tmpl, allExtensions)

	return &gen.CertificateSigningRequest{
		BasicConstraints:       basicConstraintsToProto(&tmpl),
		KeyUsages:              keyUsageToProto(&tmpl),
		ExtendedKeyUsages:      extendedKeyUsageToProto(&tmpl),
		SubjectAlternativeName: subjectAlternativeNameToProto(&tmpl),
		Subject:                subjectToProto(&tmpl),
	}
}

func ToCertificateRequest(csr *gen.CertificateSigningRequest) (*x509.CertificateRequest, error) {
	uris := make([]*url.URL, 0, len(csr.SubjectAlternativeName.Uris))
	for _, uri := range csr.SubjectAlternativeName.Uris {
		parsedUri, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		uris = append(uris, parsedUri)
	}

	ipAddresses := make([]net.IP, 0, len(csr.SubjectAlternativeName.IpAddresses))
	for _, ipAddress := range csr.SubjectAlternativeName.IpAddresses {
		parsedIpAddress := net.ParseIP(ipAddress)
		if parsedIpAddress == nil {
			return nil, fmt.Errorf("failed to parse IP address %q", ipAddress)
		}
		ipAddresses = append(ipAddresses, parsedIpAddress)
	}

	tmpl := x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  csr.BasicConstraints.IsCa,
		MaxPathLen: (func() int {
			if csr.BasicConstraints.MaxPathLen != nil {
				return int(*csr.BasicConstraints.MaxPathLen)
			}
			return 0
		})(),
		MaxPathLenZero: csr.BasicConstraints.MaxPathLen != nil,

		KeyUsage:    protoToKeyUsage(csr.KeyUsages),
		ExtKeyUsage: protoToExtendedKeyUsage(csr.ExtendedKeyUsages),

		DNSNames:       csr.SubjectAlternativeName.DnsNames,
		EmailAddresses: csr.SubjectAlternativeName.EmailAddresses,
		IPAddresses:    ipAddresses,
		URIs:           uris,
	}

	extensions, err := CertificateToExtensions(&tmpl)
	if err != nil {
		return nil, err
	}

	certReq := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            csr.Subject.Country,
			Organization:       csr.Subject.Organization,
			OrganizationalUnit: csr.Subject.OrganizationalUnit,
			Locality:           csr.Subject.Locality,
			Province:           csr.Subject.Province,
			StreetAddress:      csr.Subject.StreetAddress,
			PostalCode:         csr.Subject.PostalCode,
			SerialNumber:       csr.Subject.SerialNumber,
			CommonName:         csr.Subject.CommonName,
		},
		ExtraExtensions: extensions,
	}

	return certReq, nil
}

func keyUsageToProto(c *x509.Certificate) []gen.KeyUsage {
	protoKeyUsages := []gen.KeyUsage{}
	if c.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_digital_signature)
	}
	if c.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_content_commitment)
	}
	if c.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_key_encipherment)
	}
	if c.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_data_encipherment)
	}
	if c.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_key_agreement)
	}
	if c.KeyUsage&x509.KeyUsageCertSign != 0 {
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_cert_sign)
	}
	if c.KeyUsage&x509.KeyUsageCRLSign != 0 {
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_crl_sign)
	}
	if c.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_encipher_only)
	}
	if c.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_decipher_only)
	}

	return protoKeyUsages
}

func protoToKeyUsage(keyUsages []gen.KeyUsage) x509.KeyUsage {
	keyUsage := x509.KeyUsage(0)

	for _, protoKeyUsage := range keyUsages {
		switch protoKeyUsage {
		case gen.KeyUsage_digital_signature:
			keyUsage |= x509.KeyUsageDigitalSignature
		case gen.KeyUsage_content_commitment:
			keyUsage |= x509.KeyUsageContentCommitment
		case gen.KeyUsage_key_encipherment:
			keyUsage |= x509.KeyUsageKeyEncipherment
		case gen.KeyUsage_data_encipherment:
			keyUsage |= x509.KeyUsageDataEncipherment
		case gen.KeyUsage_key_agreement:
			keyUsage |= x509.KeyUsageKeyAgreement
		case gen.KeyUsage_cert_sign:
			keyUsage |= x509.KeyUsageCertSign
		case gen.KeyUsage_crl_sign:
			keyUsage |= x509.KeyUsageCRLSign
		case gen.KeyUsage_encipher_only:
			keyUsage |= x509.KeyUsageEncipherOnly
		case gen.KeyUsage_decipher_only:
			keyUsage |= x509.KeyUsageDecipherOnly
		}
	}

	return keyUsage
}

func extendedKeyUsageToProto(c *x509.Certificate) []gen.ExtendedKeyUsage {
	protoExtendedKeyUsages := []gen.ExtendedKeyUsage{}
	for _, usage := range c.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageAny:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_any)
		case x509.ExtKeyUsageServerAuth:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_server_auth)
		case x509.ExtKeyUsageClientAuth:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_client_auth)
		case x509.ExtKeyUsageCodeSigning:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_code_signing)
		case x509.ExtKeyUsageEmailProtection:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_email_protection)
		case x509.ExtKeyUsageIPSECEndSystem:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_ipsec_end_system)
		case x509.ExtKeyUsageIPSECTunnel:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_ipsec_tunnel)
		case x509.ExtKeyUsageIPSECUser:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_ipsec_user)
		case x509.ExtKeyUsageTimeStamping:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_time_stamping)
		case x509.ExtKeyUsageOCSPSigning:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_ocsp_signing)
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_microsoft_server_gated_crypto)
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_netscape_server_gated_crypto)
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_microsoft_commercial_code_signing)
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			protoExtendedKeyUsages = append(protoExtendedKeyUsages, gen.ExtendedKeyUsage_microsoft_kernel_code_signing)
		}
	}

	return protoExtendedKeyUsages
}

func protoToExtendedKeyUsage(extendedKeyUsages []gen.ExtendedKeyUsage) []x509.ExtKeyUsage {
	extKeyUsages := []x509.ExtKeyUsage{}

	for _, protoExtendedKeyUsage := range extendedKeyUsages {
		switch protoExtendedKeyUsage {
		case gen.ExtendedKeyUsage_any:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageAny)
		case gen.ExtendedKeyUsage_server_auth:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageServerAuth)
		case gen.ExtendedKeyUsage_client_auth:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageClientAuth)
		case gen.ExtendedKeyUsage_code_signing:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageCodeSigning)
		case gen.ExtendedKeyUsage_email_protection:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageEmailProtection)
		case gen.ExtendedKeyUsage_ipsec_end_system:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageIPSECEndSystem)
		case gen.ExtendedKeyUsage_ipsec_tunnel:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageIPSECTunnel)
		case gen.ExtendedKeyUsage_ipsec_user:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageIPSECUser)
		case gen.ExtendedKeyUsage_time_stamping:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageTimeStamping)
		case gen.ExtendedKeyUsage_ocsp_signing:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageOCSPSigning)
		case gen.ExtendedKeyUsage_microsoft_server_gated_crypto:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
		case gen.ExtendedKeyUsage_netscape_server_gated_crypto:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageNetscapeServerGatedCrypto)
		case gen.ExtendedKeyUsage_microsoft_commercial_code_signing:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
		case gen.ExtendedKeyUsage_microsoft_kernel_code_signing:
			extKeyUsages = append(extKeyUsages, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
		}
	}

	return extKeyUsages
}

func subjectAlternativeNameToProto(c *x509.Certificate) *gen.ExtensionSubjectAlternativeName {
	uris := make([]string, 0, len(c.URIs))
	for _, uri := range c.URIs {
		uris = append(uris, uri.String())
	}
	ipAddresses := make([]string, 0, len(c.IPAddresses))
	for _, ipAddress := range c.IPAddresses {
		ipAddresses = append(ipAddresses, ipAddress.String())
	}

	return &gen.ExtensionSubjectAlternativeName{
		DnsNames:       c.DNSNames,
		EmailAddresses: c.EmailAddresses,
		IpAddresses:    ipAddresses,
		Uris:           uris,
	}
}

func basicConstraintsToProto(c *x509.Certificate) *gen.ExtensionBasicConstraints {
	var maxPathLen *int32
	if c.MaxPathLen > 0 || c.MaxPathLenZero {
		maxPathLen = new(int32)
		*maxPathLen = int32(c.MaxPathLen)
	}

	return &gen.ExtensionBasicConstraints{
		IsCa:       c.IsCA,
		MaxPathLen: maxPathLen,
	}
}

func subjectToProto(c *x509.Certificate) *gen.Subject {
	return &gen.Subject{
		Country:            c.Subject.Country,
		Organization:       c.Subject.Organization,
		OrganizationalUnit: c.Subject.OrganizationalUnit,
		Locality:           c.Subject.Locality,
		Province:           c.Subject.Province,
		StreetAddress:      c.Subject.StreetAddress,
		PostalCode:         c.Subject.PostalCode,
		SerialNumber:       c.Subject.SerialNumber,
		CommonName:         c.Subject.CommonName,
	}
}
