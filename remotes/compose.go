/*
Copyright 2023 The Everoute Authors.

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

package remotes

import (
	"context"
	"fmt"
	"sync"

	"github.com/containerd/containerd/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/util/errors"
)

// NewComposeProvider create a new compose provider
func NewComposeProvider(providers ...Provider) Provider {
	return &composeProvider{
		providers: providers,
		recorder:  &imageProviderRecorder{},
	}
}

// composeProvider compose multi providers into one
type composeProvider struct {
	providers []Provider
	recorder  *imageProviderRecorder
}

func (c *composeProvider) Name() string { return "compose provider" }

func (c *composeProvider) Resolve(ctx context.Context, ref string) (name string, desc ocispec.Descriptor, err error) {
	var errlist []error

	if provider := c.recorder.get(ref); provider != nil {
		name, desc, err = provider.Resolve(ctx, ref)
		if err == nil {
			return
		}
		c.recorder.reset(ref)
		errlist = append(errlist, fmt.Errorf("%s: %s", provider.Name(), err))
	}

	for _, provider := range c.providers {
		name, desc, err = provider.Resolve(ctx, ref)
		if err == nil {
			c.recorder.set(ref, provider)
			return
		}
		errlist = append(errlist, fmt.Errorf("%s: %s", provider.Name(), err))
	}

	if len(errlist) == 0 {
		return "", desc, fmt.Errorf("no more providers")
	}
	return "", desc, errors.NewAggregate(errlist)
}

func (c *composeProvider) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	var errlist []error

	if provider := c.recorder.get(ref); provider != nil {
		fetcher, err := provider.Fetcher(ctx, ref)
		if err == nil {
			return fetcher, nil
		}
		c.recorder.reset(ref)
		errlist = append(errlist, fmt.Errorf("%s: %s", provider.Name(), err))
	}

	for _, provider := range c.providers {
		fetcher, err := provider.Fetcher(ctx, ref)
		if err == nil {
			c.recorder.set(ref, provider)
			return fetcher, nil
		}
		errlist = append(errlist, fmt.Errorf("%s: %s", provider.Name(), err))
	}

	if len(errlist) == 0 {
		return nil, fmt.Errorf("no more providers")
	}
	return nil, errors.NewAggregate(errlist)
}

type imageProviderRecorder struct {
	mu            sync.Mutex
	imageProvider map[string]Provider
}

func (r *imageProviderRecorder) get(ref string) Provider {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.imageProvider == nil {
		return nil
	}
	return r.imageProvider[ref]
}

func (r *imageProviderRecorder) set(ref string, provider Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.imageProvider == nil {
		r.imageProvider = make(map[string]Provider)
	}
	r.imageProvider[ref] = provider
}

func (r *imageProviderRecorder) reset(ref string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.imageProvider, ref)
}
