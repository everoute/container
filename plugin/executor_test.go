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

package plugin_test

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/everoute/container/client/clienttest"
	"github.com/everoute/container/model"
	"github.com/everoute/container/plugin"
)

func TestHostPluginExecutorPrecheck(t *testing.T) {
	t.Run("should do check with some precheck containers", func(t *testing.T) {
		RegisterTestingT(t)

		executor := plugin.New(clienttest.NewRuntime(time.Second), "log-prefix: ", false, nil, &model.PluginInstanceDefinition{
			PrecheckContainers: []model.ContainerDefinition{
				newContainerDefinition(rand.String(10), rand.String(10)),
			},
		})
		err := executor.Precheck(context.Background())
		Expect(err).ShouldNot(HaveOccurred())
	})

	t.Run("should do check without any precheck containers", func(t *testing.T) {
		RegisterTestingT(t)

		executor := plugin.New(clienttest.NewRuntime(time.Second), "log-prefix", false, nil, &model.PluginInstanceDefinition{})
		err := executor.Precheck(context.Background())
		Expect(err).ShouldNot(HaveOccurred())
	})

	t.Run("should do check if precheck containers already exist", func(t *testing.T) {
		RegisterTestingT(t)

		runtime := clienttest.NewRuntime(time.Second)
		precheckContainer := newContainerDefinition(rand.String(10), rand.String(10))
		container := &model.Container{Name: precheckContainer.Name, Image: precheckContainer.Image}

		executor := plugin.New(runtime, "log-prefix", false, nil, &model.PluginInstanceDefinition{
			PrecheckContainers: []model.ContainerDefinition{precheckContainer},
		})
		Expect(runtime.CreateContainer(context.Background(), container, false)).ShouldNot(HaveOccurred())
		err := executor.Precheck(context.Background())
		Expect(err).ShouldNot(HaveOccurred())
	})
}

func TestHostPluginExecutorApply(t *testing.T) {
	ctx := context.Background()
	runtime := clienttest.NewRuntime(time.Microsecond)
	executor := plugin.New(runtime, "log-prefix: ", false, nil, &model.PluginInstanceDefinition{
		InitContainers: []model.ContainerDefinition{
			newContainerDefinition(rand.String(10), rand.String(10)),
			newContainerDefinition(rand.String(10), rand.String(10)),
		},
		Containers: []model.ContainerDefinition{
			newContainerDefinition(rand.String(10), rand.String(10)),
			newContainerDefinition(rand.String(10), rand.String(10)),
		},
	})

	t.Run("should create containers and remove unused containers", func(t *testing.T) {
		RegisterTestingT(t)

		err := runtime.CreateContainer(ctx, &model.Container{Name: rand.String(10)}, false)
		Expect(err).ShouldNot(HaveOccurred())

		err = runtime.ImportImage(ctx, nil, false, rand.String(10))
		Expect(err).ShouldNot(HaveOccurred())

		Expect(executor.Apply(ctx)).ShouldNot(HaveOccurred())
		containers, err := runtime.ListContainers(ctx)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(containers).Should(HaveLen(2))

		images, err := runtime.ListImages(ctx)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(images).Should(HaveLen(2))
	})
}

func TestHostPluginExecutorRemove(t *testing.T) {
	ctx := context.Background()
	runtime := clienttest.NewRuntime(time.Microsecond)
	executor := plugin.New(runtime, "log-prefix: ", false, nil, &model.PluginInstanceDefinition{
		CleanContainers: []model.ContainerDefinition{
			newContainerDefinition(rand.String(10), rand.String(10)),
			newContainerDefinition(rand.String(10), rand.String(10)),
		},
	})

	t.Run("should remove all containers and images", func(t *testing.T) {
		RegisterTestingT(t)

		err := runtime.CreateContainer(ctx, &model.Container{Name: rand.String(10)}, false)
		Expect(err).ShouldNot(HaveOccurred())

		err = runtime.ImportImage(ctx, nil, false, rand.String(10))
		Expect(err).ShouldNot(HaveOccurred())

		Expect(executor.Remove(ctx)).ShouldNot(HaveOccurred())
		containers, err := runtime.ListContainers(ctx)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(containers).Should(HaveLen(0))

		images, err := runtime.ListImages(ctx)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(images).Should(HaveLen(0))
	})
}

func TestHostPluginExecutorHealthProbe(t *testing.T) {
	ctx := context.Background()
	runtime := clienttest.NewRuntime(time.Microsecond)
	executor := plugin.New(runtime, "log-prefix: ", false, nil, &model.PluginInstanceDefinition{
		Containers: []model.ContainerDefinition{
			newContainerDefinition(rand.String(10), rand.String(10)),
			newContainerDefinition(rand.String(10), rand.String(10)),
		},
	})

	t.Run("should check unhealthy on container not found", func(t *testing.T) {
		RegisterTestingT(t)

		result := executor.HealthProbe(ctx)
		Expect(result.Healthy).Should(BeFalse())
		Expect(result.UnHealthContainers).Should(HaveLen(2))
		Expect(result.UnHealthReason).ShouldNot(BeEmpty())
	})

	t.Run("should check healthy on healthy container", func(t *testing.T) {
		RegisterTestingT(t)

		Expect(executor.Apply(ctx)).ShouldNot(HaveOccurred())
		result := executor.HealthProbe(ctx)
		Expect(result.Healthy).Should(BeTrue())
		Expect(result.UnHealthContainers).Should(HaveLen(0))
		Expect(result.UnHealthReason).Should(BeEmpty())
	})
}

func newContainerDefinition(name, image string) model.ContainerDefinition {
	return model.ContainerDefinition{
		Name:  name,
		Image: image,
	}
}
