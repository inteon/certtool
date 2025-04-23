package libx509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"

	"libx509/gen"
	"libx509/internal"
)

func CertificateRequestDataFromProto(csr *gen.CertificateSigningRequest) (*CertificateRequestData, error) {
	subject, err := protoToRDNSequence(csr.Subject)
	if err != nil {
		return nil, err
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
	}

	extensions, err := internal.CertificateToExtensions(&tmpl)
	if err != nil {
		return nil, err
	}

	generalNames, err := protoToGeneralNames(csr.SubjectAlternativeName)
	if err != nil {
		return nil, err
	}

	if generalNames != nil {
		sansExtension, err := internal.GeneralNamesToExtension(*generalNames, len(subject) > 0)
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, sansExtension)
	}

	return &CertificateRequestData{
		Subject:    subject,
		Extensions: extensions,
	}, nil
}

func protoToGeneralNames(sans *gen.SubjectAlternativeNames) (*internal.GeneralNames, error) {
	generalNames := internal.GeneralNames{
		OtherNames:    make([]internal.AnotherName, 0, len(sans.OtherNames)),
		EDIPartyNames: make([]internal.EDIPartyName, 0, len(sans.EdiPartyNames)),
		IPAddresses:   make([]net.IP, 0, len(sans.IpAddresses)),
		RegisteredIDs: make([]asn1.ObjectIdentifier, 0, len(sans.RegisteredIds)),

		RFC822Names:                sans.Rfc_822Names,
		DNSNames:                   sans.DnsNames,
		UniformResourceIdentifiers: sans.UniformResourceIdentifiers,
	}

	for _, otherName := range sans.OtherNames {
		atav, err := protoToAttributeTypeAndValue(otherName)
		if err != nil {
			return nil, err
		}

		asn1Bytes, err := asn1.Marshal(atav.Value)
		if err != nil {
			return nil, err
		}

		generalNames.OtherNames = append(generalNames.OtherNames, internal.AnotherName{
			TypeID: atav.Type,
			Value:  asn1.RawValue{Bytes: asn1Bytes},
		})
	}

	for _, ediPartyName := range sans.EdiPartyNames {
		generalNames.EDIPartyNames = append(generalNames.EDIPartyNames, internal.EDIPartyName{
			NameAssigner: ediPartyName.NameAssigner,
			PartyName:    ediPartyName.PartyName,
		})
	}

	for _, directoryName := range sans.DirectoryNames {
		rdnSequence, err := protoToRDNSequence(directoryName)
		if err != nil {
			return nil, err
		}
		generalNames.DirectoryNames = append(generalNames.DirectoryNames, rdnSequence)
	}

	for _, ipAddress := range sans.IpAddresses {
		generalNames.IPAddresses = append(generalNames.IPAddresses, net.ParseIP(ipAddress))
	}

	for _, registeredID := range sans.RegisteredIds {
		generalNames.RegisteredIDs = append(generalNames.RegisteredIDs, protoToObjectIdentifier(registeredID))
	}

	return &generalNames, nil
}

func protoToRDNSequence(sequence *gen.RDNSequence) (pkix.RDNSequence, error) {
	rdnSequence := make(pkix.RDNSequence, 0, len(sequence.RelativeDistinguishedNames))

	for _, rdn := range sequence.RelativeDistinguishedNames {
		rdns := make([]pkix.AttributeTypeAndValue, 0, len(rdn.Attributes))

		for _, attributeTypeAndValue := range rdn.Attributes {
			atav, err := protoToAttributeTypeAndValue(attributeTypeAndValue)
			if err != nil {
				return nil, err
			}

			rdns = append(rdns, atav)
		}

		rdnSequence = append(rdnSequence, rdns)
	}

	return rdnSequence, nil
}

func protoToAttributeTypeAndValue(attributeTypeAndValue *gen.AttributeTypeAndValue) (pkix.AttributeTypeAndValue, error) {
	if attributeTypeAndValue.Value == nil {
		return pkix.AttributeTypeAndValue{}, fmt.Errorf("attribute %q has no value", attributeTypeAndValue.TypeId)
	}

	if bytes := attributeTypeAndValue.GetBytesValue(); bytes != nil {
		return pkix.AttributeTypeAndValue{
			Type:  protoToObjectIdentifier(attributeTypeAndValue.TypeId),
			Value: asn1.RawValue{FullBytes: bytes},
		}, nil
	}

	return pkix.AttributeTypeAndValue{
		Type:  protoToObjectIdentifier(attributeTypeAndValue.TypeId),
		Value: attributeTypeAndValue.GetStringValue(),
	}, nil
}

func protoToObjectIdentifier(objectIdentifier *gen.ObjectIdentifier) asn1.ObjectIdentifier {
	oid := make([]int, 0, len(objectIdentifier.ObjectIdPath))

	for _, i := range objectIdentifier.ObjectIdPath {
		oid = append(oid, int(i))
	}

	return oid
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
