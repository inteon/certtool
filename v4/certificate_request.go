package libx509

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
)

type CertificateRequestData struct {
	Subject    pkix.RDNSequence
	Extensions []pkix.Extension
}

func CertificateRequestDataFromRaw(raw []byte) (*CertificateRequestData, error) {
	req, err := x509.ParseCertificateRequest(raw)
	if err != nil {
		return nil, err
	}

	if err := req.CheckSignature(); err != nil {
		return nil, err
	}

	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(req.RawSubject, &subject); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after X.509 Subject")
	}

	return &CertificateRequestData{
		Subject:    subject,
		Extensions: req.Extensions,
	}, nil
}

func (crd *CertificateRequestData) ToRaw(rand io.Reader, sigAlgo x509.SignatureAlgorithm, priv any) (csr []byte, err error) {
	asn1Subject, err := asn1.Marshal(crd.Subject)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificateRequest(rand, &x509.CertificateRequest{
		RawSubject:         asn1Subject,
		SignatureAlgorithm: sigAlgo,
		ExtraExtensions:    crd.Extensions,
	}, priv)
}
