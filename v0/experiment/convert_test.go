package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"reflect"
	"testing"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"
)

func randomOid(random uint64) asn1.ObjectIdentifier {
	known := []asn1.ObjectIdentifier{
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
	}

	index := int(random % uint64(len(known)+3))

	if index < len(known) {
		return known[index]
	}

	return asn1.ObjectIdentifier{1, 2, 3, 4}
}

func TestRoundTripCertificateRequest(t *testing.T) {
	f := fuzz.New().NilChance(.5).NumElements(0, 10)
	f.Funcs(
		func(cr *x509.CertificateRequest, c fuzz.Continue) {
			c.Fuzz(&cr.RawSubject)
			// c.Fuzz(&cr.RawSubjectPublicKeyInfo)
			c.Fuzz(&cr.PublicKeyAlgorithm)
			var value []byte
			c.Fuzz(&value)
			cr.PublicKey = value
			c.Fuzz(&cr.Subject)
			c.Fuzz(&cr.ExtraExtensions)

			extensionIds := map[string]struct{}{}
			allExtensions := []pkix.Extension{}
			for _, val := range cr.ExtraExtensions {
				val.Id = randomOid(c.RandUint64())

				if _, ok := extensionIds[val.Id.String()]; ok {
					continue
				}

				extensionIds[val.Id.String()] = struct{}{}
				allExtensions = append(allExtensions, val)
			}
			cr.ExtraExtensions = allExtensions

			c.Fuzz(&cr.DNSNames)
			c.Fuzz(&cr.EmailAddresses)
			c.Fuzz(&cr.IPAddresses)
			c.Fuzz(&cr.URIs)
		},
		func(atv *pkix.AttributeTypeAndValue, c fuzz.Continue) {
			c.Fuzz(&atv.Type)
			var value []byte
			c.Fuzz(&value)
			atv.Value = value
		},
	)

	for i := 0; i < 10000; i++ {
		fmt.Printf("TestRoundTripCertificateRequest: %d\n", i)

		cr1 := &x509.CertificateRequest{}
		f.Fuzz(cr1)

		crt, err := CertificateRequestToCertificate(cr1)
		if err != nil {
			t.Fatal(err)
		}

		cr2, err := CertificateToCertificateRequest(crt)
		if err != nil {
			t.Fatal(err)
		}

		nilifyEmpty(&cr1.RawSubject)
		nilifyEmpty(&cr1.RawSubjectPublicKeyInfo)
		nilifyEmpty(&cr1.PublicKeyAlgorithm)
		nilifyEmpty(&cr1.PublicKey)
		nilifyEmpty(&cr1.Subject)
		nilifyEmpty(&cr1.DNSNames)
		nilifyEmpty(&cr1.EmailAddresses)
		nilifyEmpty(&cr1.IPAddresses)
		nilifyEmpty(&cr1.URIs)

		nilifyEmpty(&cr1.Extensions)
		nilifyEmpty(&cr1.ExtraExtensions)

		nilifyEmpty(&cr2.RawSubject)
		nilifyEmpty(&cr2.RawSubjectPublicKeyInfo)
		nilifyEmpty(&cr2.PublicKeyAlgorithm)
		nilifyEmpty(&cr2.PublicKey)
		nilifyEmpty(&cr2.Subject)
		nilifyEmpty(&cr2.DNSNames)
		nilifyEmpty(&cr2.EmailAddresses)
		nilifyEmpty(&cr2.IPAddresses)
		nilifyEmpty(&cr2.URIs)
		cr2.Extensions = nil
		nilifyEmpty(&cr2.ExtraExtensions)

		require.Equal(t, cr1, cr2)
	}
}

func nilifyEmpty(val interface{}) {
	v := reflect.ValueOf(val)
	if v.Kind() != reflect.Ptr {
		panic("expected pointer")
	}

	if v.IsNil() {
		return
	}

	elm := v.Elem()

	if elm.IsZero() || ((elm.Kind() == reflect.Array || elm.Kind() == reflect.Slice) && elm.Len() == 0) {
		// Set the value to nil
		elm.Set(reflect.Zero(elm.Type()))
	}
}

func TestRoundTripCertificate(t *testing.T) {
	f := fuzz.New().NilChance(.5).NumElements(0, 10)
	f.Funcs(
		func(s *string, c fuzz.Continue) {
			*s = "aaaaaaa"
		},
		func(s *[]byte, c fuzz.Continue) {
			*s = []byte("aaaaaaa")
		},
		func(crt *x509.Certificate, c fuzz.Continue) {
			// c.Fuzz(&crt.RawSubject)
			// c.Fuzz(&crt.RawIssuer)
			c.Fuzz(&crt.PublicKeyAlgorithm)
			var value []byte
			c.Fuzz(&value)
			crt.PublicKey = value
			c.Fuzz(&crt.Issuer)
			c.Fuzz(&crt.Subject)
			c.Fuzz(&crt.KeyUsage)
			c.Fuzz(&crt.ExtKeyUsage)
			c.Fuzz(&crt.ExtraExtensions)

			//extensionIds := map[string]struct{}{}
			allExtensions := []pkix.Extension{}
			/*
				for _, val := range crt.ExtraExtensions {
					val.Id = randomOid(c.RandUint64())

					if _, ok := extensionIds[val.Id.String()]; ok {
						continue
					}

					extensionIds[val.Id.String()] = struct{}{}
					allExtensions = append(allExtensions, val)
				}
			*/
			crt.ExtraExtensions = allExtensions

			c.Fuzz(&crt.BasicConstraintsValid)
			c.Fuzz(&crt.IsCA)
			c.Fuzz(&crt.MaxPathLen)
			c.Fuzz(&crt.MaxPathLenZero)

			c.Fuzz(&crt.SubjectKeyId)
			c.Fuzz(&crt.AuthorityKeyId)
			c.Fuzz(&crt.OCSPServer)
			c.Fuzz(&crt.IssuingCertificateURL)

			c.Fuzz(&crt.DNSNames)
			c.Fuzz(&crt.EmailAddresses)
			c.Fuzz(&crt.IPAddresses)
			c.Fuzz(&crt.URIs)

			c.Fuzz(&crt.PermittedDNSDomainsCritical)
			c.Fuzz(&crt.PermittedDNSDomains)
			c.Fuzz(&crt.ExcludedDNSDomains)
			c.Fuzz(&crt.PermittedIPRanges)
			c.Fuzz(&crt.ExcludedIPRanges)
			c.Fuzz(&crt.PermittedEmailAddresses)
			c.Fuzz(&crt.ExcludedEmailAddresses)
			c.Fuzz(&crt.PermittedURIDomains)
			c.Fuzz(&crt.ExcludedURIDomains)

			c.Fuzz(&crt.CRLDistributionPoints)
			c.Fuzz(&crt.PolicyIdentifiers)
		},
		func(atv *pkix.AttributeTypeAndValue, c fuzz.Continue) {
			c.Fuzz(&atv.Type)
			var value []byte
			c.Fuzz(&value)
			atv.Value = value
		},
	)

	for i := 0; i < 10000; i++ {
		fmt.Printf("TestRoundTripCertificate: %d\n", i)

		crt1 := &x509.Certificate{
			Version: 3,
		}
		f.Fuzz(crt1)

		cr, err := CertificateToCertificateRequest(crt1)
		if err != nil {
			t.Fatal(err)
		}

		crt2, err := CertificateRequestToCertificate(cr)
		if err != nil {
			t.Fatal(err)
		}

		nilifyEmpty(&crt1.Extensions)
		nilifyEmpty(&crt1.ExtraExtensions)

		crt2.Extensions = nil
		nilifyEmpty(&crt2.ExtraExtensions)

		require.Equal(t, crt1, crt2)
	}
}
