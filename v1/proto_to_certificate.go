package pki

import (
	"certtool/gen"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

func ProtoToCertificate(prot *gen.Certificate) *x509.Certificate {
	serialNumber := new(big.Int)
	if len(prot.SerialNumber) > 0 {
		parsedSerialNumber, ok := serialNumber.SetString(prot.SerialNumber, 10)
		if !ok {
			return nil // TODO: handle error
		}
		serialNumber = parsedSerialNumber
	} else {
		serialNumber = nil
	}

	subject := &pkix.Name{}
	if prot.Subject != nil {
		rdnSequence := ProtoToRDNSequence(prot.Subject)
		subject.FillFromRDNSequence(&rdnSequence)
	}

	var notBefore time.Time
	if prot.NotBefore != nil {
		notBefore = prot.NotBefore.AsTime()
	}

	var notAfter time.Time
	if prot.NotAfter != nil {
		notAfter = prot.NotAfter.AsTime()
	}

	cert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      *subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	extensions := make([]pkix.Extension, 0)
	for _, ext := range prot.Extensions {
		cert.Extensions = append(cert.Extensions, ProtoToExtension(ext))
	}

	OverwriteFromExtensions(cert, extensions)

	return cert
}

func ProtoToRDNSequence(prot *gen.RDNSequence) pkix.RDNSequence {
	rdn := make(pkix.RDNSequence, 0, len(prot.RelativeDistinguishedNames))

	for _, name := range prot.RelativeDistinguishedNames {
		rdn = append(rdn, ProtoToRelativeDistinguishedNameSET(name))
	}

	return rdn
}

func ProtoToRelativeDistinguishedNameSET(prot *gen.RDN) pkix.RelativeDistinguishedNameSET {
	rdn := make(pkix.RelativeDistinguishedNameSET, 0, len(prot.Attributes))

	for _, attr := range prot.Attributes {
		rdn = append(rdn, ProtoToAttributeTypeAndValue(attr))
	}

	return rdn
}

func ProtoToAttributeTypeAndValue(prot *gen.AttributeTypeAndValue) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{
		Type:  ProtoToObjectIdentifier(prot.Type),
		Value: prot.Value,
	}
}

func ProtoToObjectIdentifier(prot *gen.ObjectIdentifier) asn1.ObjectIdentifier {
	oid := asn1.ObjectIdentifier(make(asn1.ObjectIdentifier, 0, len(prot.ObjectIdPath)))

	for _, id := range prot.ObjectIdPath {
		oid = append(oid, int(id))
	}

	return oid
}

func ProtoToExtension(prot *gen.Extension) pkix.Extension {
	return pkix.Extension{
		Id:       ProtoToObjectIdentifier(prot.ObjectId),
		Critical: prot.Critical,
		Value:    prot.Value,
	}
}
