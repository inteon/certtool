package main

import (
	"certtool/gen"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"

	"k8s.io/apimachinery/pkg/util/errors"
)

type CertificateBuilder struct {
	cert x509.Certificate
	errs []error
}

func (c *CertificateBuilder) SetKeyUsage(e *gen.ExtensionKeyUsage) error {
	if e == nil {
		return nil
	}

	keyUsage := x509.KeyUsage(0)
	for _, usage := range e.KeyUsages {
		switch usage {
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
	c.cert.KeyUsage = keyUsage

	return nil
}

func (c *CertificateBuilder) SetExtendedKeyUsage(e *gen.ExtensionExtendedKeyUsage) error {
	if e == nil {
		return nil
	}

	extendedKeyUsage := make([]x509.ExtKeyUsage, 0, len(e.ExtendedKeyUsages))
	for _, usage := range e.ExtendedKeyUsages {
		switch usage {
		case gen.ExtendedKeyUsage_any:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageAny)
		case gen.ExtendedKeyUsage_server_auth:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageServerAuth)
		case gen.ExtendedKeyUsage_client_auth:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageClientAuth)
		case gen.ExtendedKeyUsage_code_signing:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageCodeSigning)
		case gen.ExtendedKeyUsage_email_protection:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageEmailProtection)
		case gen.ExtendedKeyUsage_ipsec_end_system:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageIPSECEndSystem)
		case gen.ExtendedKeyUsage_ipsec_tunnel:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageIPSECTunnel)
		case gen.ExtendedKeyUsage_ipsec_user:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageIPSECUser)
		case gen.ExtendedKeyUsage_time_stamping:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageTimeStamping)
		case gen.ExtendedKeyUsage_ocsp_signing:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageOCSPSigning)
		case gen.ExtendedKeyUsage_microsoft_server_gated_crypto:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
		case gen.ExtendedKeyUsage_netscape_server_gated_crypto:
			extendedKeyUsage = append(extendedKeyUsage, x509.ExtKeyUsageNetscapeServerGatedCrypto)
		}
	}
	c.cert.ExtKeyUsage = extendedKeyUsage

	return nil
}

func (c *CertificateBuilder) SetSubjectAlternativeName(e *gen.ExtensionSubjectAlternativeName) error {
	if e == nil {
		return nil
	}

	c.cert.DNSNames = e.DnsNames
	c.cert.EmailAddresses = e.EmailAddresses
	ipAdresses := make([]net.IP, 0, len(e.IpAddresses))
	for _, ip := range e.IpAddresses {
		ipAdresses = append(ipAdresses, net.ParseIP(ip))
	}
	c.cert.IPAddresses = ipAdresses
	uris := make([]*url.URL, 0, len(e.Uris))
	for _, uri := range e.Uris {
		parsedUrl, err := url.Parse(uri)
		if err != nil {
			c.errs = append(c.errs, err)
			continue
		}
		uris = append(uris, parsedUrl)
	}
	c.cert.URIs = uris
	return nil
}

func (c *CertificateBuilder) SetBasicConstraints(e *gen.ExtensionBasicConstraints) error {
	if e == nil {
		return nil
	}

	c.cert.BasicConstraintsValid = true
	c.cert.IsCA = e.IsCa
	if e.MaxPathLen != nil {
		c.cert.MaxPathLen = int(*e.MaxPathLen)
		c.cert.MaxPathLenZero = true
	} else {
		c.cert.MaxPathLen = 0
		c.cert.MaxPathLenZero = false
	}
	return nil
}

func (c *CertificateBuilder) SetSubject(e *gen.Subject) error {
	if e == nil {
		return nil
	}

	c.cert.Subject.Country = e.Country
	c.cert.Subject.Organization = e.Organization
	c.cert.Subject.OrganizationalUnit = e.OrganizationalUnit
	c.cert.Subject.Locality = e.Locality
	c.cert.Subject.Province = e.Province
	c.cert.Subject.StreetAddress = e.StreetAddress
	c.cert.Subject.PostalCode = e.PostalCode
	c.cert.Subject.SerialNumber = e.SerialNumber
	c.cert.Subject.CommonName = e.CommonName
	return nil
}

func (c *CertificateBuilder) SetValidity(notBefore time.Time, notAfter time.Time) error {
	c.cert.NotBefore = notBefore
	c.cert.NotAfter = notAfter
	return nil
}

func (c *CertificateBuilder) SetPublicKey(pub any) error {
	c.cert.PublicKey = pub
	return nil
}

func (c *CertificateBuilder) BuildAndSign(
	ca *x509.Certificate,
	caKey any,
) ([]byte, error) {
	if len(c.errs) > 0 {
		return nil, errors.NewAggregate(c.errs)
	}

	if c.cert.PublicKey == nil {
		return nil, fmt.Errorf("public key is required")
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&c.cert,
		ca,
		c.cert.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, err
	}

	return certBytes, nil
}
