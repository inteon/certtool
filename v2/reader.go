package main

import (
	"certtool/gen"
	"crypto/x509"
	"crypto/x509/pkix"
)

type RequestReader struct {
	tmpl x509.Certificate
}

func FromCertificateRequest(csr *x509.CertificateRequest) *RequestReader {
	tmpl := x509.Certificate{}
	tmpl.RawSubject = csr.RawSubject
	tmpl.Subject = csr.Subject

	allExtensions := make([]pkix.Extension, 0, len(csr.Extensions)+len(csr.ExtraExtensions))
	allExtensions = append(allExtensions, csr.Extensions...)
	allExtensions = append(allExtensions, csr.ExtraExtensions...)

	OverwriteFromExtensions(&tmpl, allExtensions)

	return &RequestReader{
		tmpl: tmpl,
	}
}

func (c *RequestReader) hasExtension(oid []int) bool {
	for _, ext := range c.tmpl.Extensions {
		if ext.Id.Equal(oid) {
			return true
		}
	}
	return false
}

func (c *RequestReader) GetKeyUsage() *gen.ExtensionKeyUsage {
	if !c.hasExtension(oidExtensionKeyUsage) {
		return nil
	}

	protoKeyUsages := []gen.KeyUsage{}
	switch {
	case c.tmpl.KeyUsage&x509.KeyUsageDigitalSignature != 0:
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_digital_signature)
	case c.tmpl.KeyUsage&x509.KeyUsageContentCommitment != 0:
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_content_commitment)
	case c.tmpl.KeyUsage&x509.KeyUsageKeyEncipherment != 0:
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_key_encipherment)
	case c.tmpl.KeyUsage&x509.KeyUsageDataEncipherment != 0:
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_data_encipherment)
	case c.tmpl.KeyUsage&x509.KeyUsageKeyAgreement != 0:
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_key_agreement)
	case c.tmpl.KeyUsage&x509.KeyUsageCertSign != 0:
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_cert_sign)
	case c.tmpl.KeyUsage&x509.KeyUsageCRLSign != 0:
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_crl_sign)
	case c.tmpl.KeyUsage&x509.KeyUsageEncipherOnly != 0:
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_encipher_only)
	case c.tmpl.KeyUsage&x509.KeyUsageDecipherOnly != 0:
		protoKeyUsages = append(protoKeyUsages, gen.KeyUsage_decipher_only)
	}

	return &gen.ExtensionKeyUsage{
		KeyUsages: protoKeyUsages,
	}
}

func (c *RequestReader) GetExtendedKeyUsage() *gen.ExtensionExtendedKeyUsage {
	if !c.hasExtension(oidExtensionExtendedKeyUsage) {
		return nil
	}

	protoExtendedKeyUsages := []gen.ExtendedKeyUsage{}
	for _, usage := range c.tmpl.ExtKeyUsage {
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

	return &gen.ExtensionExtendedKeyUsage{
		ExtendedKeyUsages: protoExtendedKeyUsages,
	}
}

func (c *RequestReader) GetSubjectAlternativeName() *gen.ExtensionSubjectAlternativeName {
	if !c.hasExtension(oidExtensionSubjectAltName) {
		return nil
	}

	uris := make([]string, 0, len(c.tmpl.URIs))
	for _, uri := range c.tmpl.URIs {
		uris = append(uris, uri.String())
	}
	ipAddresses := make([]string, 0, len(c.tmpl.IPAddresses))
	for _, ipAddress := range c.tmpl.IPAddresses {
		ipAddresses = append(ipAddresses, ipAddress.String())
	}

	return &gen.ExtensionSubjectAlternativeName{
		DnsNames:       c.tmpl.DNSNames,
		EmailAddresses: c.tmpl.EmailAddresses,
		IpAddresses:    ipAddresses,
		Uris:           uris,
	}
}

func (c *RequestReader) GetBasicConstraints() *gen.ExtensionBasicConstraints {
	if !c.hasExtension(oidExtensionBasicConstraints) {
		return nil
	}

	var maxPathLen *int32
	if c.tmpl.MaxPathLen > 0 || c.tmpl.MaxPathLenZero {
		maxPathLen = new(int32)
		*maxPathLen = int32(c.tmpl.MaxPathLen)
	}

	return &gen.ExtensionBasicConstraints{
		IsCa:       c.tmpl.IsCA,
		MaxPathLen: maxPathLen,
	}
}

func (c *RequestReader) GetSubject() *gen.Subject {
	return &gen.Subject{
		Country:            c.tmpl.Subject.Country,
		Organization:       c.tmpl.Subject.Organization,
		OrganizationalUnit: c.tmpl.Subject.OrganizationalUnit,
		Locality:           c.tmpl.Subject.Locality,
		Province:           c.tmpl.Subject.Province,
		StreetAddress:      c.tmpl.Subject.StreetAddress,
		PostalCode:         c.tmpl.Subject.PostalCode,
		SerialNumber:       c.tmpl.Subject.SerialNumber,
		CommonName:         c.tmpl.Subject.CommonName,
	}
}
