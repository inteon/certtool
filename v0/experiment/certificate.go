package pki

import (
	"crypto/x509/pkix"
	"math/big"
	"time"
)

type Certificate struct {
	SerialNumber        *big.Int
	Issuer              pkix.RDNSequence
	NotBefore, NotAfter time.Time

	Subject    pkix.RDNSequence
	Extensions []pkix.Extension
}

type CertificateRequest struct {
	Subject       pkix.RDNSequence
	RawAttributes []pkix.Extension
}
