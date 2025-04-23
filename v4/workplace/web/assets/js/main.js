/**
 * Copyright 2023 Undistro Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AceEditor } from "./editor.js";

// Add the following polyfill for Microsoft Edge 17/18 support:
// <script src="https://cdn.jsdelivr.net/npm/text-encoding@0.7.0/lib/encoding.min.js"></script>
// (see https://caniuse.com/#feat=textencoder)
if (!WebAssembly.instantiateStreaming) {
  // polyfill
  WebAssembly.instantiateStreaming = async (resp, importObject) => {
    const source = await (await resp).arrayBuffer();
    return await WebAssembly.instantiate(source, importObject);
  };
}

const celEditor = new AceEditor("cel-input");
const csrEditor = new AceEditor("csr-input");
const dataEditor = new AceEditor("data-input");
const identityEditor = new AceEditor("identity-input");

function toYAML() {
  const csr = csrEditor.getValue();

  dataEditor.setValue("x509ToYAML...", -1);
  const result = x509ToYAML(csr);

  const { output: resultOutput } = result;
  dataEditor.setValue(resultOutput, -1);
}

function toCSR() {
  const yaml = dataEditor.getValue();

  csrEditor.setValue("yamlToX509...", -1);
  const result = yamlToX509(yaml);

  const { output: resultOutput } = result;
  csrEditor.setValue(resultOutput, -1);
}

function run() {
  const data = dataEditor.getValue();
  const identity = identityEditor.getValue();
  const expression = celEditor.getValue();
  const output = document.getElementById("output");

  output.value = "Evaluating...";
  const result = celEval(expression, data, identity);

  const { output: resultOutput, isError } = result;
  output.value = `${resultOutput}`;
  output.style.color = isError ? "red" : "white";
}

(async function loadAndRunGoWasm() {
  const go = new Go();

  const buffer = pako.ungzip(
    await (await fetch("assets/main.wasm.gz")).arrayBuffer()
  );

  // A fetched response might be decompressed twice on Firefox.
  // See https://bugzilla.mozilla.org/show_bug.cgi?id=610679
  if (buffer[0] === 0x1f && buffer[1] === 0x8b) {
    buffer = pako.ungzip(buffer);
  }

  WebAssembly.instantiate(buffer, go.importObject)
    .then((result) => {
      go.run(result.instance);
      document.getElementById("run").disabled = false;
      document.getElementById("toYAML").disabled = false;
      document.getElementById("toCSR").disabled = false;
      document.getElementById("output").placeholder =
        "Press 'Run' to evaluate your CEL expression.";
    })
    .catch((err) => {
      console.error(err);
    });
})();

const toYAMLButton = document.getElementById("toYAML");
const toCSRButton = document.getElementById("toCSR");
const runButton = document.getElementById("run");

toYAMLButton.addEventListener("click", toYAML);
toCSRButton.addEventListener("click", toCSR);
runButton.addEventListener("click", run);
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && event.code === "Enter") {
    run();
  }
});
