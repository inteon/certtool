package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"certtool/internal/error_match"
)

func Test_newCertificateNameGenerator(t *testing.T) {
	type testCase struct {
		celTemplator string
		csr          *x509.CertificateRequest

		expectedCertificate  *x509.Certificate
		expectedCompileError *error_match.Matcher
		expectedRuntimeError *error_match.Matcher
	}

	testCases := []testCase{
		{
			celTemplator: `Certificate{
				CertificateAuthorityIdentifier: request.getSANs().dns_names[0].orValue("not found"),
			}`,
			csr: &x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName:   "common-name",
					Organization: []string{"organization-1", "organization-2"},
				},
			},
			expectedCertificate: &x509.Certificate{},
		},
	}

	for idx, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("test-case-%d", idx), func(t *testing.T) {
			generator, err := newCertificateNameGenerator(tc.celTemplator)
			if !ptr.Deref(tc.expectedCompileError, *error_match.NoError())(t, err) {
				t.Fail()
			}
			if err != nil {
				return
			}

			certificate, err := generator(tc.csr)
			if !ptr.Deref(tc.expectedRuntimeError, *error_match.NoError())(t, err) {
				t.Fail()
			}
			if err != nil {
				return
			}

			require.EqualValues(t, tc.expectedCertificate, certificate)
		})
	}
}
