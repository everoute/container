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

package clienttest

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"

	"github.com/everoute/container/client"
	"github.com/everoute/container/model"
)

type runtime struct {
	followWaitTime time.Duration
	images         map[string]images.Image
	containers     map[string]*model.Container
}

// NewRuntime create a mock runtime, any images or containers record to memory only
func NewRuntime(followWaitTime time.Duration) client.Runtime {
	return &runtime{
		followWaitTime: followWaitTime,
		images:         make(map[string]images.Image),
		containers:     make(map[string]*model.Container),
	}
}

func (r *runtime) Platform() platforms.MatchComparer     { return platforms.All }
func (r *runtime) ContainerdClient() *containerd.Client  { return &containerd.Client{} }
func (r *runtime) Namespace() string                     { return "unknown" }
func (r *runtime) ConfigRuntime(context.Context) error   { return nil }
func (r *runtime) RemoveNamespace(context.Context) error { return nil }

func (r *runtime) RecommendedRuntimeInfo(context.Context, *model.Container) *containers.RuntimeInfo {
	return &containers.RuntimeInfo{}
}

func (r *runtime) NodeExecute(ctx context.Context, name string, commands ...string) error {
	if len(commands) == 0 {
		return nil
	}
	return exec.CommandContext(ctx, commands[0], commands[1:]...).Run()
}

func (r *runtime) ImportImages(ctx context.Context, refs ...string) error {
	for _, ref := range refs {
		r.images[ref] = images.Image{Name: ref}
	}
	return nil
}

func (r *runtime) ListImages(ctx context.Context) ([]images.Image, error) {
	var allImages []images.Image

	for _, i := range r.images {
		allImages = append(allImages, i)
	}

	return allImages, nil
}

func (r *runtime) RemoveImage(ctx context.Context, ref string) error {
	delete(r.images, ref)
	return nil
}

func (r *runtime) GetImage(ctx context.Context, ref string) (*images.Image, bool, error) {
	i, ok := r.images[ref]
	return &i, ok, nil
}

func (r *runtime) CreateContainer(ctx context.Context, container *model.Container, follow bool) error {
	if _, ok := r.containers[container.Name]; ok {
		return fmt.Errorf("container with name %s exist", container.Name)
	}

	r.containers[container.Name] = container
	if follow {
		time.Sleep(r.followWaitTime)
	}
	return nil
}

func (r *runtime) UpdateContainer(_ context.Context, container *model.Container, _ *client.ContainerUpdateOptions) error {
	if _, ok := r.containers[container.Name]; !ok {
		return fmt.Errorf("container with name %s not exist", container.Name)
	}
	r.containers[container.Name] = container
	return nil
}

func (r *runtime) RemoveContainer(ctx context.Context, containerID string) error {
	delete(r.containers, containerID)
	return nil
}

func (r *runtime) GetContainer(ctx context.Context, containerID string) (*model.Container, error) {
	container, ok := r.containers[containerID]
	if !ok {
		return nil, fmt.Errorf("container %s not found", containerID)
	}
	return container, nil
}

func (r *runtime) ListContainers(ctx context.Context) ([]*model.Container, error) {
	containers := make([]*model.Container, 0, len(r.containers))
	for _, container := range r.containers {
		containers = append(containers, container)
	}
	return containers, nil
}

func (r *runtime) GetContainerStatus(ctx context.Context, containerID string) (client.ContainerStatus, error) {
	_, ok := r.containers[containerID]
	if !ok {
		return client.ContainerStatus{}, fmt.Errorf("container %s not found", containerID)
	}
	return client.ContainerStatus{Status: containerd.Status{Status: containerd.Running}}, nil
}

func (r *runtime) ExecCommand(ctx context.Context, containerID string, commands []string) (*containerd.ExitStatus, error) {
	_, ok := r.containers[containerID]
	if !ok {
		return nil, fmt.Errorf("container %s not found", containerID)
	}
	return containerd.NewExitStatus(0, time.Now(), nil), nil
}

func (r *runtime) Close() error {
	return nil
}
