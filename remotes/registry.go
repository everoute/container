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
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
)

// RegistryProviderOptions are used to configure a new register provider
type RegistryProviderOptions docker.ResolverOptions

// NewRegistryProvider create a new provider to a registry
func NewRegistryProvider(options RegistryProviderOptions) Provider {
	return registryProvider{
		Resolver: docker.NewResolver(docker.ResolverOptions(options)),
	}
}

type registryProvider struct{ remotes.Resolver }

func (registryProvider) Name() string { return "registry provider" }
