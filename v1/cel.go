package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"

	"certtool/gen"
)

type CertificateTemplator func(*x509.CertificateRequest) (*x509.Certificate, error)

func newCertificateNameGenerator(celTemplator string) (CertificateTemplator, error) {
	// celTypeCertificate := cel.ObjectType("Certificate")
	celTypeCertiifcateSigningRequest := cel.ObjectType("CertificateSigningRequest")
	// celTypeExtensionKeyUsage := cel.ObjectType("ExtensionKeyUsage")
	// celTypeExtensionPrivateKeyUsagePeriod := cel.ObjectType("ExtensionPrivateKeyUsagePeriod")
	celTypeExtensionSubjectAlternativeName := cel.ObjectType("ExtensionSubjectAlternativeName")
	// celTypeExtensionBasicConstraints := cel.ObjectType("ExtensionBasicConstraints")
	// celTypeExtensionExtendedKeyUsage := cel.ObjectType("ExtensionExtendedKeyUsage")

	celTypeOptionalExtensionSubjectAlternativeName := cel.OptionalType(celTypeExtensionSubjectAlternativeName)

	env, err := cel.NewEnv(
		ext.Strings(),
		cel.OptionalTypes(),
		cel.Types(&gen.Certificate{}),
		cel.Types(&gen.CertificateSigningRequest{}),
		cel.Types(&gen.ExtensionSubjectAlternativeName{}),
		cel.Variable("request", celTypeCertiifcateSigningRequest),
		cel.Function("getSANs",
			cel.MemberOverload("CertificateSigningRequest_getSANs",
				[]*cel.Type{celTypeCertiifcateSigningRequest},
				celTypeOptionalExtensionSubjectAlternativeName,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					csrObj, err := val.ConvertToNative(reflect.TypeOf(&gen.CertificateSigningRequest{}))
					if err != nil {
						panic(err)
					}

					csr := csrObj.(*gen.CertificateSigningRequest)

					var foundExtension *pkix.Extension
					for _, ext := range csr.GetExtensions() {
						extension := ProtoToExtension(ext)
						if extension.Id.Equal(oidExtensionSubjectAltName) {
							foundExtension = &extension
						}
					}

					if foundExtension == nil {
						return types.OptionalOf(nil)
					}

					cert := x509.Certificate{}
					OverwriteFromExtensions(&cert, []pkix.Extension{*foundExtension})

					ipAddresses := make([]string, 0, len(cert.IPAddresses))
					for _, ip := range cert.IPAddresses {
						ipAddresses = append(ipAddresses, ip.String())
					}

					uris := make([]string, 0, len(cert.URIs))
					for _, uri := range cert.URIs {
						uris = append(uris, uri.String())
					}

					return types.OptionalOf(types.DefaultTypeAdapter.NativeToValue(
						gen.ExtensionSubjectAlternativeName{
							DnsNames:       cert.DNSNames,
							EmailAddresses: cert.EmailAddresses,
							IpAddresses:    ipAddresses,
							Uris:           uris,
						}))
				}),
			),
		),
	)
	if err != nil {
		return nil, err
	}

	ast, iss := env.Compile(celTemplator)
	// Check iss for compilation errors.
	if iss.Err() != nil {
		return nil, iss.Err()
	}

	if !reflect.DeepEqual(ast.OutputType(), cel.ObjectType("Certificate")) {
		return nil, fmt.Errorf("got %v, wanted %v output type", ast.OutputType(), cel.ObjectType("Certificate"))
	}

	prg, err := env.Program(ast)
	if err != nil {
		return nil, err
	}

	return func(csr *x509.CertificateRequest) (*x509.Certificate, error) {
		out, _, err := prg.Eval(map[string]any{
			"request": CertificateRequestToProto(csr),
		})
		if err != nil {
			return nil, err
		}

		result, err := out.ConvertToNative(reflect.TypeOf(&gen.Certificate{}))
		if err != nil {
			return nil, err
		}

		cert := result.(*gen.Certificate)

		return ProtoToCertificate(cert), nil
	}, nil
}
