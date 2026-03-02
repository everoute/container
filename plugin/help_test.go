/*
Copyright 2025 The Everoute Authors.

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

package plugin

import (
	"reflect"
	"testing"

	"github.com/opencontainers/runtime-spec/specs-go"

	"github.com/everoute/container/model"
)

func TestIgnoreEnvFields_SkipsFields(t *testing.T) {
    old := &specs.Spec{Process: &specs.Process{Env: []string{"A=1", "B=2", "C=3"}}}
    new := &specs.Spec{Process: &specs.Process{Env: []string{"A=4", "B=5"}}}

    s := &SkipEnv{Fields: []string{"B", "C"}}
    s.IgnoreEnvFields(old, new)

    wantOld := []string{"A=1"}
    wantNew := []string{"A=4"}

    if !reflect.DeepEqual(old.Process.Env, wantOld) {
        t.Fatalf("old env = %v, want %v", old.Process.Env, wantOld)
    }
    if !reflect.DeepEqual(new.Process.Env, wantNew) {
        t.Fatalf("new env = %v, want %v", new.Process.Env, wantNew)
    }
}

func TestIgnoreEnvFields_HandlesNil(t *testing.T) {
    s := &SkipEnv{Fields: []string{"X"}}

    // should not panic on nil specs
    s.IgnoreEnvFields(nil, nil)

    // should not panic when Process or Env is nil
    s.IgnoreEnvFields(&specs.Spec{}, &specs.Spec{})
    s.IgnoreEnvFields(&specs.Spec{Process: &specs.Process{}}, &specs.Spec{Process: &specs.Process{}})
}

func TestGetCustomDiffProcessFunc(t *testing.T) {
    diffs := []model.CustomDiffDefinition{{Type: model.SkipCompareEnvField, Fields: []string{"FOO"}}}
    funcs := GetCustomDiffProcessFunc(diffs)
    if len(funcs) != 1 {
        t.Fatalf("len(funcs) = %d, want 1", len(funcs))
    }

    old := &specs.Spec{Process: &specs.Process{Env: []string{"FOO=1", "BAR=2"}}}
    new := &specs.Spec{Process: &specs.Process{Env: []string{"FOO=3", "BAR=4"}}}

    funcs[0](old, new)

    wantOld := []string{"BAR=2"}
    wantNew := []string{"BAR=4"}
    if !reflect.DeepEqual(old.Process.Env, wantOld) {
        t.Fatalf("old env = %v, want %v", old.Process.Env, wantOld)
    }
    if !reflect.DeepEqual(new.Process.Env, wantNew) {
        t.Fatalf("new env = %v, want %v", new.Process.Env, wantNew)
    }

    // unknown types should be ignored
    diffs2 := []model.CustomDiffDefinition{{Type: "unknown-type"}}
    funcs2 := GetCustomDiffProcessFunc(diffs2)
    if len(funcs2) != 0 {
        t.Fatalf("len(funcs2) = %d, want 0", len(funcs2))
    }
}
