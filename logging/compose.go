/*
Copyright 2024 The Everoute Authors.

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

package logging

import (
	"context"

	"github.com/everoute/container/client"
	"github.com/everoute/container/model"
	"github.com/everoute/container/sync"
)

// NewComposeFactory returns a new composeFactory
func NewComposeFactory(factories ...Factory) Factory { return composeFactory{factories: factories} }

// composeFactory compose multi factories into one
type composeFactory struct{ factories []Factory }

func (c composeFactory) Name() string { return "compose-factory" }

func (c composeFactory) ProviderFor(runtime client.Runtime, instance *model.PluginInstanceDefinition) Provider {
	providers := make([]Provider, 0, len(c.factories))
	for _, f := range c.factories {
		providers = append(providers, f.ProviderFor(runtime, instance))
	}
	return multiProviders{providers: providers}
}

type multiProviders struct{ providers []Provider }

func (m multiProviders) SetupLogging(ctx context.Context) error {
	wg := sync.NewGroup(0)
	for _, p := range m.providers {
		p := p
		wg.Go(func() error { return p.SetupLogging(ctx) })
	}
	return wg.WaitResult()
}

func (m multiProviders) RemoveLogging(ctx context.Context) error {
	wg := sync.NewGroup(0)
	for _, p := range m.providers {
		p := p
		wg.Go(func() error { return p.RemoveLogging(ctx) })
	}
	return wg.WaitResult()
}
