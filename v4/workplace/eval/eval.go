// Copyright 2023 Undistro Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package eval

import (
	"fmt"
	"reflect"

	"playground/libx509/gen"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	tpb "google.golang.org/protobuf/types/known/timestamppb"
	k8s "k8s.io/apiserver/pkg/cel/library"
	"sigs.k8s.io/yaml"
)

var celEnvOptions = []cel.EnvOption{
	cel.EagerlyValidateDeclarations(true),
	cel.DefaultUTCTimeZone(true),
	ext.Strings(ext.StringsVersion(2)),
	cel.CrossTypeNumericComparisons(true),
	cel.OptionalTypes(),
	k8s.URLs(),
	k8s.Regex(),
	k8s.Lists(),
	k8s.Quantity(),

	cel.Types(&gen.CertificateSigningRequest{}),
	cel.Types(&gen.Certificate{}),
}

var celProgramOptions = []cel.ProgramOption{
	cel.EvalOptions(cel.OptOptimize, cel.OptTrackCost),
}

// Eval evaluates the cel expression against the given input
func Eval(exp string, yamlCR string, identityString string) (string, error) {
	var identity any
	if err := yaml.Unmarshal([]byte(identityString), &identity); err != nil {
		return "", fmt.Errorf("failed to unmarshal identity string: %w", err)
	}

	jsonBytes, err := yaml.YAMLToJSON([]byte(yamlCR))
	if err != nil {
		return "", fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	cr := gen.CertificateSigningRequest{}

	if err := protojson.Unmarshal(jsonBytes, &cr); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	inputVars := []cel.EnvOption{
		cel.Variable("identity", cel.DynType),
		cel.Variable("cr", cel.ObjectType("CertificateSigningRequest")),
		cel.Variable("now", cel.ObjectType("google.protobuf.Timestamp")),
	}
	env, err := cel.NewEnv(append(celEnvOptions, inputVars...)...)
	if err != nil {
		return "", fmt.Errorf("failed to create CEL env: %w", err)
	}
	ast, issues := env.Compile(exp)
	if issues != nil {
		return "", fmt.Errorf("failed to compile the CEL expression: %s", issues.String())
	}
	prog, err := env.Program(ast, celProgramOptions...)
	if err != nil {
		return "", fmt.Errorf("failed to instantiate CEL program: %w", err)
	}
	val, _, err := prog.Eval(map[string]interface{}{
		"cr":       &cr,
		"now":      tpb.Now(),
		"identity": identity,
	})
	if err != nil {
		return "", fmt.Errorf("failed to evaluate: %w", err)
	}
	jsonData, err := val.ConvertToNative(reflect.TypeOf(&structpb.Value{}))
	if err != nil {
		return "", fmt.Errorf("failed to marshal the output: %w", err)
	}
	out := protojson.Format(jsonData.(*structpb.Value))
	return out, nil
}
