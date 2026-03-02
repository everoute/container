package plugin

import (
	"strings"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/samber/lo"
	"k8s.io/klog/v2"

	"github.com/everoute/container/model"
)

type CustomDiffProcessFunc func(_, _ *specs.Spec)

type SkipEnv struct {
	Fields []string
}

func (s *SkipEnv) IgnoreEnvFields(oldS, newS *specs.Spec) {
	if len(s.Fields) == 0 {
		return
	}

	for _, spec := range []*specs.Spec{oldS, newS} {
		if spec == nil {
			continue
		}
		if spec.Process == nil {
			continue
		}
		if spec.Process.Env == nil {
			continue
		}
		spec.Process.Env = lo.Filter(spec.Process.Env, func(env string, _ int) bool {
			return !lo.Contains(s.Fields, strings.Split(env, "=")[0])
		})
	}
}

func GetCustomDiffProcessFunc(customDiffs []model.CustomDiffDefinition) []CustomDiffProcessFunc {
	var funcs []CustomDiffProcessFunc
	for _, diff := range customDiffs {
		switch diff.Type {
		case model.SkipCompareEnvField:
			funcs = append(funcs, (&SkipEnv{Fields: diff.Fields}).IgnoreEnvFields)
		default:
			// unknown custom diff type, skip
			klog.Errorf("unknown custom diff type: %s, skip", diff.Type)
		}
	}

	return funcs
}
