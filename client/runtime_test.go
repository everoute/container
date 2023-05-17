/*
Copyright 2022 The Everoute Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"context"
	"fmt"
	"testing"

	"github.com/containerd/containerd/oci"
	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/gomega"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestWithSpecPatch(t *testing.T) {

	RegisterTestingT(t)

	testCases := []struct {
		specPatch   string
		expectError bool
		expectSpec  *specs.Spec
	}{
		{
			specPatch:   "[}",
			expectError: true,
		},
		{
			specPatch:   "[{}]",
			expectError: true,
		},
		{
			specPatch:  "",
			expectSpec: &specs.Spec{},
		},
		{
			specPatch:  "[]",
			expectSpec: &specs.Spec{},
		},
		{
			specPatch:  `[{"op":"replace","path":"/hostname","value":"localhost"}]`,
			expectSpec: &specs.Spec{Hostname: "localhost"},
		},
		{
			specPatch:  `[{"op":"add","path":"/hostname","value":"localhost"}]`,
			expectSpec: &specs.Spec{Hostname: "localhost"},
		},
		{
			specPatch:  `[{"op":"add","path":"/hostname","value":"localhost"},{"op":"add","path":"/hostname","value":"localhost"}]`,
			expectSpec: &specs.Spec{Hostname: "localhost"},
		},
		{
			specPatch:  `[{"op":"add","path":"/hostname","value":"localhost"},{"op":"remove","path":"/hostname"}]`,
			expectSpec: &specs.Spec{},
		},
		{
			specPatch:  `[{"op":"replace","path":"/hostname","value":"localhost"},{"op":"remove","path":"/hostname"}]`,
			expectSpec: &specs.Spec{},
		},
		{
			specPatch:  `[{"op":"add","path":"/annotations","value":{"a1":"b1","a2":"b2"}},{"op":"remove","path":"/annotations/a1"}]`,
			expectSpec: &specs.Spec{Annotations: map[string]string{"a2": "b2"}},
		},
	}

	for index, tc := range testCases {
		t.Run(fmt.Sprintf("case%d", index), func(t *testing.T) {
			spec := &specs.Spec{}
			err := oci.ApplyOpts(context.Background(), nil, nil, spec, withSpecPatch([]byte(tc.specPatch)))
			if err != nil != tc.expectError {
				t.Fatalf("expect error: %t actual error: %t error detail: %s", tc.expectError, err != nil, err)
			}

			if tc.expectError {
				return
			}

			diff := cmp.Diff(spec, tc.expectSpec)
			if diff != "" {
				t.Fatalf("unexpect spec with diff = %s", diff)
			}
		})
	}
}
