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

//go:build js && wasm

package main

import (
	"errors"
	"syscall/js"

	"playground/eval"
	"playground/libx509"
)

func main() {
	evalFunc := js.FuncOf(evalWrapper)
	js.Global().Set("celEval", evalFunc)

	parseFunc := js.FuncOf(x509ToYAMLWrapper)
	js.Global().Set("x509ToYAML", parseFunc)

	parseFunc = js.FuncOf(yamlToX509Wrapper)
	js.Global().Set("yamlToX509", parseFunc)

	defer evalFunc.Release()
	<-make(chan bool)
}

// x509ToYAMLWrapper
func x509ToYAMLWrapper(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return response("", errors.New("invalid arguments"))
	}
	is := args[0].String()

	output, err := libx509.X509ToYAML(is)
	if err != nil {
		return response("", err)
	}

	return response(output, nil)
}

// yamlToX509Wrapper
func yamlToX509Wrapper(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return response("", errors.New("invalid arguments"))
	}
	is := args[0].String()

	output, err := libx509.YAMLToX509(is)
	if err != nil {
		return response("", err)
	}

	return response(output, nil)
}

// evalWrapper wraps the eval function with `syscall/js` parameters
func evalWrapper(_ js.Value, args []js.Value) any {
	if len(args) != 3 {
		return response("", errors.New("invalid arguments"))
	}
	exp := args[0].String()
	is := args[1].String()
	identityString := args[2].String()

	output, err := eval.Eval(exp, is, identityString)
	if err != nil {
		return response("", err)
	}
	return response(output, nil)
}

func response(out string, err error) any {
	if err != nil {
		out = err.Error()
	}
	return map[string]any{"output": out, "isError": err != nil}
}
