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

package logging_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/everoute/container/client"
	"github.com/everoute/container/client/clienttest"
	"github.com/everoute/container/logging"
	"github.com/everoute/container/model"
)

var (
	runtime    client.Runtime
	configPath string
	factory    logging.Factory
)

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "logrotate")
	if err != nil {
		panic(fmt.Sprintf("create temp dir: %s", err))
	}
	defer os.RemoveAll(tmp)

	configPath = filepath.Join(tmp, "runtime-logging")
	runtime = clienttest.NewRuntime(time.Second)
	factory = logging.NewLogrotateFactory(configPath)

	os.Exit(m.Run())
}

func TestSetupLogging(t *testing.T) {
	ctx := context.Background()

	t.Run("should setup logging config without containers", func(t *testing.T) {
		RegisterTestingT(t)

		provider := factory.ProviderFor(runtime, &model.PluginInstanceDefinition{})
		Expect(provider.SetupLogging(ctx)).ShouldNot(HaveOccurred())
	})

	t.Run("should setup logging config with some containers", func(t *testing.T) {
		RegisterTestingT(t)

		provider := factory.ProviderFor(runtime, &model.PluginInstanceDefinition{Containers: []model.ContainerDefinition{
			{Logging: &model.LoggingDefinition{Path: "/path/to/log01", MaxSize: 20, MaxFile: 10}},
			{Logging: &model.LoggingDefinition{Path: "/path/to/log02", MaxSize: 20, MaxFile: 10}},
		}})
		Expect(provider.SetupLogging(ctx)).ShouldNot(HaveOccurred())

		out, err := ioutil.ReadFile(configPath)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).Should(Equal("include " + configPath + ".d\n"))

		out, err = ioutil.ReadFile(configPath + ".d/" + runtime.Namespace())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).ShouldNot(BeEmpty())
	})
}

func TestRemoveLogging(t *testing.T) {
	ctx := context.Background()

	t.Run("should remove logging config without containers", func(t *testing.T) {
		RegisterTestingT(t)

		provider := factory.ProviderFor(runtime, &model.PluginInstanceDefinition{})
		Expect(provider.SetupLogging(ctx)).ShouldNot(HaveOccurred())
		Expect(provider.RemoveLogging(ctx)).ShouldNot(HaveOccurred())
	})

	t.Run("should remove logging config with some containers", func(t *testing.T) {
		RegisterTestingT(t)

		provider := factory.ProviderFor(runtime, &model.PluginInstanceDefinition{Containers: []model.ContainerDefinition{
			{Logging: &model.LoggingDefinition{Path: "/path/to/log01", MaxSize: 20, MaxFile: 10}},
			{Logging: &model.LoggingDefinition{Path: "/path/to/log02", MaxSize: 20, MaxFile: 10}},
		}})
		Expect(provider.SetupLogging(ctx)).ShouldNot(HaveOccurred())

		out, err := ioutil.ReadFile(configPath)
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).Should(Equal("include " + configPath + ".d\n"))

		out, err = ioutil.ReadFile(configPath + ".d/" + runtime.Namespace())
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(out)).ShouldNot(BeEmpty())

		Expect(provider.RemoveLogging(ctx)).ShouldNot(HaveOccurred())
		_, err = os.Stat(configPath + ".d/" + runtime.Namespace())
		Expect(err).Should(HaveOccurred())
	})
}
