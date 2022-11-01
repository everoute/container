/*
Copyright 2021 The Everoute Authors.

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
	"io"

	"github.com/containerd/containerd/images"

	"github.com/everoute/container/model"
	"github.com/everoute/container/resolver"
)

type Runtime interface {
	ImageManager
	ContainerManager
	io.Closer
}

// ImageManager contains methods to manipulate images. The methods are thread-safe.
type ImageManager interface {
	// ImportImage imports specify images from resolver.NewReadCloserFunc
	ImportImage(ctx context.Context, newReadCloserFunc resolver.NewReadCloserFunc, imageRefs ...string) error

	// ListImages list all images in containerd
	ListImages(ctx context.Context) ([]images.Image, error)

	// RemoveImage remove an image from containerd
	RemoveImage(ctx context.Context, ref string) error

	// GetImage return image details
	GetImage(ctx context.Context, ref string) (*images.Image, bool, error)
}

// ContainerManager contains methods to manipulate containers managed by a
// container runtime. The methods are thread-safe.
type ContainerManager interface {
	// CreateContainer creates a new container.
	CreateContainer(ctx context.Context, container *model.Container, follow bool) error

	// RemoveContainer removes the container.
	RemoveContainer(ctx context.Context, containerID string) error

	// GetContainer return container by containerID
	GetContainer(ctx context.Context, containerID string) (*model.Container, error)

	// ListContainers list containers in the namespace
	ListContainers(ctx context.Context) ([]*model.Container, error)
}
