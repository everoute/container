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

package logging

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/alessio/shellescape"
	"github.com/google/uuid"

	"github.com/everoute/container/client"
	"github.com/everoute/container/model"
)

// NewLogrotateFactory create a new Factory with logrotate
func NewLogrotateFactory(configPath string) Factory {
	return &logrotate{
		aggregateConfigPath: configPath,
		dropInConfigDir:     filepath.Join(filepath.Dir(configPath), filepath.Base(configPath)+".d"),
	}
}

type logrotate struct {
	aggregateConfigPath string
	dropInConfigDir     string

	runtime  client.Runtime
	instance *model.PluginInstanceDefinition
}

func (l *logrotate) Name() string { return "logrotate" }

func (l *logrotate) ProviderFor(runtime client.Runtime, instance *model.PluginInstanceDefinition) Provider {
	return &logrotate{
		aggregateConfigPath: l.aggregateConfigPath,
		dropInConfigDir:     l.dropInConfigDir,
		runtime:             runtime,
		instance:            instance,
	}
}

const (
	defaultMaxSize = 10
	defaultMaxFile = 10
)

func (l *logrotate) SetupLogging(ctx context.Context) error {
	configs := make([]model.LoggingDefinition, 0, len(l.instance.Containers))

	for _, container := range l.instance.Containers {
		if container.Logging != nil && container.Logging.Path != "" {
			config := *container.Logging
			if config.MaxSize == 0 {
				config.MaxSize = defaultMaxSize
			}
			if config.MaxFile == 0 {
				config.MaxFile = defaultMaxFile
			}
			configs = append(configs, config)
		}
	}

	if len(configs) == 0 {
		return nil
	}

	dropInConfig, err := makeupConfig(configs)
	if err != nil {
		return fmt.Errorf("makeup config: %s", err)
	}

	commands := makeupCommands(
		printQuotef("echo %s > %s", fmt.Sprintf("include %s", l.dropInConfigDir), l.aggregateConfigPath),
		printQuotef("mkdir -p %s", l.dropInConfigDir),
		printQuotef("echo %s | base64 -d > %s", dropInConfig, filepath.Join(l.dropInConfigDir, l.runtime.Namespace())),
	)

	containerName := "setup-logging-%s" + uuid.New().String()
	return l.runtime.NodeExecute(ctx, containerName, commands...)
}

func (l *logrotate) RemoveLogging(ctx context.Context) error {
	containerName := "remove-logging-%s" + uuid.New().String()
	return l.runtime.NodeExecute(ctx, containerName, "rm", "-f", filepath.Join(l.dropInConfigDir, l.runtime.Namespace()))
}

//go:embed logrotate
var configTemplate string

func makeupConfig(configs []model.LoggingDefinition) (string, error) {
	buf := bytes.NewBuffer(nil)

	err := template.Must(template.New("config").Parse(configTemplate)).Execute(buf, configs)
	if err != nil {
		return "", fmt.Errorf("execute template %s", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func makeupCommands(commands ...string) []string {
	return []string{"bash", "-c", strings.Join(commands, " && ")}
}

func printQuotef(format string, args ...string) string {
	quoteArgs := make([]interface{}, 0, len(args))
	for _, arg := range args {
		quoteArgs = append(quoteArgs, shellescape.Quote(arg))
	}
	return fmt.Sprintf(format, quoteArgs...)
}
