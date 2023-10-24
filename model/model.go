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

package model

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/opencontainers/runtime-spec/specs-go"
)

type Container struct {
	// Name uniquely identifies the container in one node.
	Name string

	// Image specifies the image reference used for a container.
	Image string
	// ConfigContent specifies the config content for a container.
	ConfigContent []ConfigFile
	// Mounts configures additional mounts (on top of Root).
	Mounts []specs.Mount

	// Process configures the container process.
	Process Process
	// CgroupParent specifies the path to cgroups that are created and/or joined by the container.
	// The path is expected to be relative to the cgroups mountpoint.
	CgroupParent string
	// MemoryLimit specifies the memory limit for this container
	MemoryLimit uint64
	// CPUPeriod and CPUQuota specifies the CPU limit to this container
	CPUPeriod uint64
	CPUQuota  int64
	// Privilege specifies the privilege mode for container
	Privilege bool
	// Capabilities required by container
	Capabilities []string
	// Rlimits specifies rlimit options to apply to the process.
	Rlimits []specs.POSIXRlimit
	// SpecPatches is a list of jsonpatch for container oci spec.
	// The patches applied in order.
	SpecPatches []json.RawMessage
}

const (
	// StdOutputStream redirect output to the system stdout
	// StdOutputStream are only available when connected to the local containerd
	StdOutputStream string = "StdOutputStream"
)

type Process struct {
	// Args specifies the binary and arguments for the application to execute.
	Args []string
	// Env populates the process environment for the process.
	Env []string
	// WorkingDir is the current working directory for the process and must be
	// relative to the container's root.
	WorkingDir string
	// Path for store the log (STDOUT and STDERR) on the host.
	LogPath string
	// RestartPolicy to apply when a container exits.
	RestartPolicy RestartPolicy
}

// RestartPolicy describes how the container should be restarted.
// Only one of the following restart policies may be specified.
// If none of the following policies is specified, the default one
// is RestartPolicyAlways.
type RestartPolicy string

const (
	RestartPolicyAlways RestartPolicy = "Always"
	RestartPolicyNever  RestartPolicy = "Never"
)

// ConfigFile provide file config overlay container rootfs.
type ConfigFile struct {
	// Path specifies the file path, e.g /etc/everoute/config.yaml
	Path string
	// FileMode specifies file mode bits.
	FileMode os.FileMode
	// FileContent specifies config file content.
	FileContent []byte
}

func (c *Container) Complete() *Container {
	// complete mount type and options
	for index := range c.Mounts {
		if c.Mounts[index].Type == "" {
			c.Mounts[index].Type = "none"
		}
		if len(c.Mounts[index].Options) == 0 {
			c.Mounts[index].Options = []string{"rbind"}
		}
	}

	if c.Process.LogPath == "" {
		c.Process.LogPath = fmt.Sprintf("/var/log/%s.log", c.Name)
	}

	if c.Process.RestartPolicy == "" {
		c.Process.RestartPolicy = RestartPolicyNever
	}

	if c.Process.WorkingDir == "" {
		c.Process.WorkingDir = "/"
	}

	return c
}
