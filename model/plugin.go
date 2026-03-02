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

package model

import "time"

// PluginInstanceDefinition contains container definitions about how
// to install a plugin instance
type PluginInstanceDefinition struct {
	ExtraRequireImages []ExtraRequireImage   `yaml:"extra_require_images,omitempty"`
	PrecheckContainers []ContainerDefinition `yaml:"precheck_containers,omitempty"`
	InitContainers     []ContainerDefinition `yaml:"init_containers,omitempty"`
	Containers         []ContainerDefinition `yaml:"containers"`
	PostContainers     []ContainerDefinition `yaml:"post_containers,omitempty"`
	CleanContainers    []ContainerDefinition `yaml:"clean_containers,omitempty"`
}

type ExtraRequireImage struct {
	Name   string `yaml:"name"`
	Unpack bool   `yaml:"unpack,omitempty"`
}

type ContainerDefinition struct {
	Name          string                  `yaml:"name"`
	Image         string                  `yaml:"image"`
	Mounts        []MountDefinition       `yaml:"mounts,omitempty"`
	Process       ProcessDefinition       `yaml:"process"`
	Logging       *LoggingDefinition      `yaml:"logging,omitempty"`
	Metrics       *MetricsDefinition      `yaml:"metrics,omitempty"`
	Resources     *ResourceDefinition     `yaml:"resources,omitempty"`
	Runtime       *RuntimeDefinition      `yaml:"runtime,omitempty"`
	UpdatePolicy  *UpdatePolicyDefinition `yaml:"update_policy,omitempty"`
	StartupProbe  *ContainerProbe         `yaml:"startup_probe,omitempty"`
	LivenessProbe *ContainerProbe         `yaml:"liveness_probe,omitempty"`
	SpecPatches   []string                `yaml:"spec_patches,omitempty"`
}

type MountDefinition struct {
	Destination string   `yaml:"destination"`
	Source      string   `yaml:"source"`
	Type        string   `yaml:"type,omitempty"`
	Options     []string `yaml:"options,omitempty"`
}

type ProcessDefinition struct {
	Command    string   `yaml:"command"`
	Args       []string `yaml:"args,omitempty"`
	Env        []string `yaml:"env,omitempty"`
	WorkingDir string   `yaml:"working_dir,omitempty"`
	LogPath    string   `yaml:"log_path,omitempty"` // Deprecated, use LoggingDefinition.Path
}

// LoggingDefinition of the plugin containers
type LoggingDefinition struct {
	Path     string   `yaml:"path,omitempty"`
	Includes []string `yaml:"includes,omitempty"` // Includes log files to rotate
	MaxSize  uint64   `yaml:"max_size,omitempty"` // MB
	MaxFile  uint64   `yaml:"max_file,omitempty"`
}

type MetricsDefinition struct {
	Endpoint  string        `yaml:"endpoint"`
	Interval  time.Duration `yaml:"interval,omitempty"`
	Timeout   time.Duration `yaml:"timeout,omitempty"`
	TLSConfig *TLSConfig    `yaml:"tls_config,omitempty"`
}

type ResourceDefinition struct {
	Privileged   bool          `yaml:"privileged,omitempty"`
	CgroupParent string        `yaml:"cgroup_parent,omitempty"`
	Memory       uint64        `yaml:"memory,omitempty"`
	CPUPeriod    uint64        `yaml:"cpu_period,omitempty"`
	CPUQuota     int64         `yaml:"cpu_quota,omitempty"`
	Capabilities []string      `yaml:"capabilities,omitempty"`
	Rlimits      []POSIXRlimit `yaml:"rlimits,omitempty"`

	// Note: devices major and minor read from the client node
	// This can produce errors when the client and containerd on the different nodes
	// Use mounts and enable privileged to access devices in this case
	Devices []string `yaml:"devices,omitempty"`
}

type RuntimeDefinition struct {
	NoPivotRoot   bool   `yaml:"no_pivot_root,omitempty"`
	BinaryName    string `yaml:"binary_name,omitempty"`
	SystemdCgroup bool   `yaml:"systemd_cgroup,omitempty"`
}

type UpdatePolicyDefinition struct {
	OnNoChange     UpdatePolicyMode       `yaml:"on_no_change,omitempty"`
	PreRestartHook *Hook                  `yaml:"pre_restart_hook,omitempty"` // exec when the previous container state is running
	CustomDiffs    []CustomDiffDefinition `yaml:"custom_diffs,omitempty"`
}

type CustomDiffDefinition struct {
	Type   CustomDiffType `yaml:"type"`
	Fields []string       `yaml:"fields,omitempty"`
}

type Hook struct {
	ExecCommand     []string `yaml:"exec_command,omitempty"`
	ExecTimeout     *int     `yaml:"exec_timeout,omitempty"`     // 0 means no timeout, default to 10(s)
	RetriesInterval *int     `yaml:"retries_interval,omitempty"` // 0 means no waiting, default to 1(s)
	MaxRetries      int      `yaml:"max_retries,omitempty"`      // 0 means no retries, default to 0
	IgnoreFailed    bool     `yaml:"ignore_failed,omitempty"`    // ignore on hook failed
}

type UpdatePolicyMode string

const (
	UpdatePolicyModeSkip    UpdatePolicyMode = "skip"
	UpdatePolicyModeRestart UpdatePolicyMode = "restart"
)

type CustomDiffType string

const (
	SkipCompareEnvField CustomDiffType = "skip-env-field"
)

type POSIXRlimit struct {
	Type string `yaml:"type"`
	Hard uint64 `yaml:"hard"`
	Soft uint64 `yaml:"soft"`
}

type ContainerProbe struct {
	HTTPGet      string   `yaml:"http_get,omitempty" json:"http_get,omitempty"`           // http get url to check
	ExecCommand  []string `yaml:"exec_command,omitempty" json:"exec_command,omitempty"`   // container exec command to check
	CheckTimeout int      `yaml:"check_timeout,omitempty" json:"check_timeout,omitempty"` // http get or exec timeout
	ProbeTimeout int      `yaml:"probe_timeout,omitempty" json:"probe_timeout,omitempty"` // total timeout, only valid for startup_probe
}

type PluginInstanceHealthResult struct {
	Healthy             bool      `json:"healthy"`
	LastHealthCheckTime time.Time `json:"last_health_check_time"`
	UnHealthContainers  []string  `json:"un_health_containers,omitempty"`
	UnHealthReason      string    `json:"un_health_reason,omitempty"`
}

type TLSConfig struct {
	CAFile             string `yaml:"ca_file,omitempty"`
	CrtFile            string `yaml:"crt_file,omitempty"`
	KeyFile            string `yaml:"key_file,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
}
