package libx509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"libx509/gen"
	"libx509/internal"
)

func (crd *CertificateRequestData) ToProto() (*gen.CertificateSigningRequest, error) {
	tmpl := x509.Certificate{}
	internal.OverwriteFromExtensions(&tmpl, crd.Extensions)

	sequence, err := rdnSequenceToProto(crd.Subject)
	if err != nil {
		return nil, err
	}

	generalNames, err := internal.GeneralNamesFromExtensions(crd.Extensions)
	if err != nil {
		return nil, err
	}

	sans, err := generalNamesToProto(generalNames)
	if err != nil {
		return nil, err
	}

	return &gen.CertificateSigningRequest{
		BasicConstraints:       basicConstraintsToProto(&tmpl),
		Subject:                sequence,
		SubjectAlternativeName: sans,
		KeyUsages:              keyUsageToProto(&tmpl),
		ExtendedKeyUsages:      extendedKeyUsageToProto(&tmpl),
	}, nil
}

func generalNamesToProto(gns internal.GeneralNames) (*gen.SubjectAlternativeNames, error) {
	otherNames := make([]*gen.AttributeTypeAndValue, 0, len(gns.OtherNames))
	for _, on := range gns.OtherNames {
		otherName, err := attributeTypeAndValueToProto(pkix.AttributeTypeAndValue{
			Type:  on.TypeID,
			Value: on.Value.Bytes,
		})
		if err != nil {
			return nil, err
		}
		otherNames = append(otherNames, otherName)
	}

	ediPartyNames := make([]*gen.EDIPartyName, 0, len(gns.EDIPartyNames))
	for _, epn := range gns.EDIPartyNames {
		ediPartyNames = append(ediPartyNames, &gen.EDIPartyName{
			NameAssigner: epn.NameAssigner,
			PartyName:    epn.PartyName,
		})
	}

	directoryNames := make([]*gen.RDNSequence, 0, len(gns.DirectoryNames))
	for _, dn := range gns.DirectoryNames {
		directoryName, err := rdnSequenceToProto(dn)
		if err != nil {
			return nil, err
		}
		directoryNames = append(directoryNames, directoryName)
	}

	ipAddresses := make([]string, 0, len(gns.IPAddresses))
	for _, ip := range gns.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}

	registeredIDs := make([]*gen.ObjectIdentifier, 0, len(gns.RegisteredIDs))
	for _, oid := range gns.RegisteredIDs {
		registeredIDs = append(registeredIDs, objectIdentifierToProto(oid))
	}

	return &gen.SubjectAlternativeNames{
		OtherNames:   otherNames,
		Rfc_822Names: gns.RFC822Names,
		DnsNames:     gns.DNSNames,
		// X400Addresses:              gns.X400Addresses,
		DirectoryNames:             directoryNames,
		EdiPartyNames:              ediPartyNames,
		UniformResourceIdentifiers: gns.UniformResourceIdentifiers,
		IpAddresses:                ipAddresses,
		RegisteredIds:              registeredIDs,
	}, nil
}

func rdnSequenceToProto(seq pkix.RDNSequence) (*gen.RDNSequence, error) {
	rdns := make([]*gen.RDN, 0, len(seq))
	for _, rdn := range seq {
		genRDN := &gen.RDN{
			Attributes: make([]*gen.AttributeTypeAndValue, 0, len(rdn)),
		}
		for _, atv := range rdn {
			atav, err := attributeTypeAndValueToProto(atv)
			if err != nil {
				return nil, err
			}
			genRDN.Attributes = append(genRDN.Attributes, atav)
		}
		rdns = append(rdns, genRDN)
	}

	return &gen.RDNSequence{
		RelativeDistinguishedNames: rdns,
	}, nil
}

func attributeTypeAndValueToProto(atv pkix.AttributeTypeAndValue) (*gen.AttributeTypeAndValue, error) {
	atav := &gen.AttributeTypeAndValue{
		TypeId: objectIdentifierToProto(atv.Type),
	}

	sv, isString := atv.Value.(string)
	if isString {
		atav.Value = &gen.AttributeTypeAndValue_StringValue{StringValue: sv}
		return atav, nil
	}

	asn1Bytes, err := asn1.Marshal(atv.Value)
	if err != nil {
		return nil, err
	}

	atav.Value = &gen.AttributeTypeAndValue_BytesValue{BytesValue: asn1Bytes}
	return atav, nil
}

func objectIdentifierToProto(oid asn1.ObjectIdentifier) *gen.ObjectIdentifier {
	path := make([]int32, 0, len(oid))
	for _, i := range oid {
		path = append(path, int32(i))
	}
	return &gen.ObjectIdentifier{
		ObjectIdPath: path,
	}
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

func basicConstraintsToProto(c *x509.Certificate) *gen.BasicConstraints {
	var maxPathLen *int32
	if c.MaxPathLen > 0 || c.MaxPathLenZero {
		maxPathLen = new(int32)
		*maxPathLen = int32(c.MaxPathLen)
	}

	return &gen.BasicConstraints{
		IsCa:       c.IsCA,
		MaxPathLen: maxPathLen,
	}
}
