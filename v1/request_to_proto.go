package pki

import (
	"certtool/gen"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

func CertificateRequestToProto(cr *x509.CertificateRequest) *gen.CertificateSigningRequest {
	prot := &gen.CertificateSigningRequest{
		Subject:    RDNSequenceToProto(cr.Subject.ToRDNSequence()),
		Extensions: make([]*gen.Extension, 0, len(cr.Extensions)),
	}

	for _, ext := range cr.Extensions {
		prot.Extensions = append(prot.Extensions, ExtensionToProto(ext))
	}

	return prot
}

func RDNSequenceToProto(rdn pkix.RDNSequence) *gen.RDNSequence {
	prot := &gen.RDNSequence{
		RelativeDistinguishedNames: make([]*gen.RDN, 0, len(rdn)),
	}

	for _, rdn := range rdn {
		prot.RelativeDistinguishedNames = append(prot.RelativeDistinguishedNames, RelativeDistinguishedNameSETToProto(rdn))
	}

	return prot
}

func RelativeDistinguishedNameSETToProto(rdn pkix.RelativeDistinguishedNameSET) *gen.RDN {
	prot := &gen.RDN{
		Attributes: make([]*gen.AttributeTypeAndValue, 0, len(rdn)),
	}

	for _, attr := range rdn {
		prot.Attributes = append(prot.Attributes, AttributeTypeAndValueToProto(attr))
	}

	return prot
}

func AttributeTypeAndValueToProto(attr pkix.AttributeTypeAndValue) *gen.AttributeTypeAndValue {
	value, ok := attr.Value.(string)
	if !ok {
		return nil // TODO: handle other types
	}

	return &gen.AttributeTypeAndValue{
		Type:  ObjectIdentifierToProto(attr.Type),
		Value: value,
	}
}

func ExtensionToProto(ext pkix.Extension) *gen.Extension {
	return &gen.Extension{
		ObjectId: ObjectIdentifierToProto(ext.Id),
		Critical: ext.Critical,
		Value:    ext.Value,
	}
}

func ObjectIdentifierToProto(oid asn1.ObjectIdentifier) *gen.ObjectIdentifier {
	prot := &gen.ObjectIdentifier{
		ObjectIdPath: make([]int32, 0, len(oid)),
	}
	for _, id := range oid {
		prot.ObjectIdPath = append(prot.ObjectIdPath, int32(id))
	}
	return prot
}
