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
	"context"

	"github.com/samber/lo"
)

type ContextKey string

const (
	ContextSkipNoChange ContextKey = "skip-no-change"
)

func SetSkipNoChange(ctx context.Context, skip bool) context.Context {
	return context.WithValue(ctx, ContextSkipNoChange, skip)
}

func GetSkipNoChange(ctx context.Context) bool {
	v := ctx.Value(ContextSkipNoChange)
	skip, ok := v.(bool)
	return lo.If(ok, skip).Else(false)
}

func WithSkipNoChange(ctx context.Context) context.Context {
	return SetSkipNoChange(ctx, true)
}
