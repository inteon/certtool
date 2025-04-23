package internal

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"strconv"
	"unicode"
)

// OtherName represents the ASN.1 structure of the same name. See RFC
// 5280, section 4.2.1.6.
/*
	AnotherName ::= SEQUENCE {
		type-id    OBJECT IDENTIFIER,
		value      [0] EXPLICIT ANY DEFINED BY type-id }
*/
type AnotherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"tag:0,explicit"`
}

// EDIPartyName represents the ASN.1 structure of the same name. See RFC
// 5280, section 4.2.1.6.
/*
	EDIPartyName ::= SEQUENCE {
		nameAssigner            [0]     DirectoryString OPTIONAL,
		partyName               [1]     DirectoryString }
*/
type EDIPartyName struct {
	NameAssigner *string `asn1:"tag:0,optional"`
	PartyName    string  `asn1:"tag:1"`
}

/*
	GeneralName ::= CHOICE {
	     otherName                       [0]     AnotherName,
	     rfc822Name                      [1]     IA5String,
	     dnsName                         [2]     IA5String,
	     x400Address                     [3]     ORAddress,
	     directoryName                   [4]     Name,
	     ediPartyName                    [5]     EDIPartyName,
	     uniformResourceIdentifier       [6]     IA5String,
	     ipAddress                       [7]     OCTET STRING,
		 registeredID                    [8]     OBJECT IDENTIFIER }
*/
const (
	nameTypeOtherName                 = 0
	nameTypeRFC822Name                = 1
	nameTypeDNSName                   = 2
	nameTypeX400Address               = 3
	nameTypeDirectoryName             = 4
	nameTypeEDIPartyName              = 5
	nameTypeUniformResourceIdentifier = 6
	nameTypeIPAddress                 = 7
	nameTypeRegisteredID              = 8
)

type GeneralNames struct {
	OtherNames                 []AnotherName
	RFC822Names                []string
	DNSNames                   []string
	X400Addresses              []asn1.RawValue
	DirectoryNames             []pkix.RDNSequence
	EDIPartyNames              []EDIPartyName
	UniformResourceIdentifiers []string
	IPAddresses                []net.IP
	RegisteredIDs              []asn1.ObjectIdentifier
}

func GeneralNamesFromExtensions(exts []pkix.Extension) (gns GeneralNames, err error) {
	for _, ext := range exts {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			return UnmarshallGeneralNames(ext.Value)
		}
	}
	return
}

func GeneralNamesToExtension(gns GeneralNames, hasSubject bool) (pkix.Extension, error) {
	byteValue, err := MarshallGeneralNames(gns)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       oidExtensionSubjectAltName,
		Critical: !hasSubject,
		Value:    byteValue,
	}, nil
}

func MarshallGeneralNames(gns GeneralNames) ([]byte, error) {
	var rawValues []asn1.RawValue
	addMarshalable := func(tag int, val interface{}) error {
		b, err := asn1.Marshal(val)
		if err != nil {
			return err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: tag, Class: 2, Bytes: b})
		return nil
	}
	addIA5String := func(tag int, val string) error {
		if err := isIA5String(val); err != nil {
			return err
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: tag, Class: 2, Bytes: []byte(val)})
		return nil
	}

	for _, val := range gns.OtherNames {
		if err := addMarshalable(nameTypeOtherName, val); err != nil {
			return nil, err
		}
	}
	for _, val := range gns.RFC822Names {
		if err := addMarshalable(nameTypeRFC822Name, val); err != nil {
			return nil, err
		}
	}
	for _, val := range gns.DNSNames {
		if err := addIA5String(nameTypeDNSName, val); err != nil {
			return nil, err
		}
	}
	for _, val := range gns.X400Addresses {
		if err := addMarshalable(nameTypeX400Address, val); err != nil {
			return nil, err
		}
	}
	for _, val := range gns.DirectoryNames {
		if err := addMarshalable(nameTypeDirectoryName, val); err != nil {
			return nil, err
		}
	}
	for _, val := range gns.EDIPartyNames {
		if err := addMarshalable(nameTypeEDIPartyName, val); err != nil {
			return nil, err
		}
	}
	for _, val := range gns.UniformResourceIdentifiers {
		if err := addIA5String(nameTypeUniformResourceIdentifier, val); err != nil {
			return nil, err
		}
	}
	for _, rawIP := range gns.IPAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: nameTypeIPAddress, Class: 2, Bytes: ip})
	}
	for _, val := range gns.RegisteredIDs {
		if err := addMarshalable(nameTypeRegisteredID, val); err != nil {
			return nil, err
		}
	}
	return asn1.Marshal(rawValues)
}

func isIA5String(s string) error {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return fmt.Errorf("x509: %q cannot be encoded as an IA5String", s)
		}
	}

	return nil
}

func UnmarshallGeneralNames(value []byte) (gns GeneralNames, err error) {
	var seq asn1.RawValue
	var rest []byte
	if rest, err = asn1.Unmarshal(value, &seq); err != nil {
		return
	} else if len(rest) != 0 {
		err = errors.New("x509: trailing data after X.509 extension")
		return
	}

	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		err = asn1.StructuralError{Msg: "bad SAN sequence"}
		return
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return
		}

		switch v.Tag {
		case nameTypeOtherName:
			var anotherName AnotherName
			if _, err = asn1.Unmarshal(v.Bytes, &anotherName); err != nil {
				return
			}
			gns.OtherNames = append(gns.OtherNames, anotherName)
		case nameTypeDNSName:
			gns.DNSNames = append(gns.DNSNames, string(v.Bytes))
		case nameTypeRFC822Name:
			gns.RFC822Names = append(gns.RFC822Names, string(v.Bytes))
		case nameTypeX400Address:
			gns.X400Addresses = append(gns.X400Addresses, v)
		case nameTypeDirectoryName:
			var rdn pkix.RDNSequence
			if _, err = asn1.Unmarshal(v.Bytes, &rdn); err != nil {
				return
			}
			gns.DirectoryNames = append(gns.DirectoryNames, rdn)
		case nameTypeEDIPartyName:
			var edipn EDIPartyName
			if _, err = asn1.Unmarshal(v.Bytes, &edipn); err != nil {
				return
			}
			gns.EDIPartyNames = append(gns.EDIPartyNames, edipn)
		case nameTypeUniformResourceIdentifier:
			gns.UniformResourceIdentifiers = append(gns.UniformResourceIdentifiers, string(v.Bytes))
		case nameTypeIPAddress:
			switch len(v.Bytes) {
			case net.IPv4len, net.IPv6len:
				gns.IPAddresses = append(gns.IPAddresses, v.Bytes)
			default:
				err = errors.New("x509: cannot parse IP address of length " + strconv.Itoa(len(v.Bytes)))
				return
			}
		case nameTypeRegisteredID:
			var oid asn1.ObjectIdentifier
			if _, err = asn1.Unmarshal(v.Bytes, &oid); err != nil {
				return
			}
			gns.RegisteredIDs = append(gns.RegisteredIDs, oid)
		default:
			err = asn1.StructuralError{Msg: "bad SAN choice"}
			return
		}
	}

	return
}
