package parse

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"playground/parse/gen"

	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

func X509ToYAML(x509CertReq string) (string, error) {
	var derBytes []byte
	block, _ := pem.Decode([]byte(x509CertReq))
	if block == nil {
		return "", fmt.Errorf("failed to parse Request as PEM data, attempting to treat Request as DER encoded for compatibility reasons")
	} else {
		derBytes = block.Bytes
	}

	req, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return "", err
	}

	protoReq := FromCertificateRequest(req)

	jsonBytes, err := protojson.MarshalOptions{
		UseProtoNames: true,
	}.Marshal(protoReq)
	if err != nil {
		return "", err
	}

	yamlBytes, err := yaml.JSONToYAML(jsonBytes)
	if err != nil {
		return "", err
	}

	return string(yamlBytes), nil
}

func YAMLToX509(yamlBytes string) (string, error) {
	jsonBytes, err := yaml.YAMLToJSON([]byte(yamlBytes))
	if err != nil {
		return "", fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	cr := gen.CertificateSigningRequest{}

	if err := protojson.Unmarshal(jsonBytes, &cr); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	x509CertReq, err := ToCertificateRequest(&cr)
	if err != nil {
		return "", err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return "", err
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, x509CertReq, privateKey)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})), nil
}
