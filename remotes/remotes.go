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

	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Resolver provides remotes based on a locator
type Resolver remotes.Resolver

type StoreProvider interface {
	Provider
	Store
}

// Provider resolve and fetch image content
type Provider interface {
	// Name returns the name of the Provider
	Name() string

	// Resolve attempts to resolve the reference into a name and descriptor
	Resolve(ctx context.Context, ref string) (name string, desc ocispec.Descriptor, err error)

	// Fetcher returns a new fetcher for the provided reference
	Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error)
}

// Store and interact with images
type Store interface {
	Get(ctx context.Context, ref string) (images.Image, error)
	List(ctx context.Context) ([]images.Image, error)
}

// ProviderResolver adapt Provider as Resolver
type ProviderResolver struct {
	Provider
}

func (ProviderResolver) Pusher(context.Context, string) (remotes.Pusher, error) {
	return nil, fmt.Errorf("not implemented by provider")
}
