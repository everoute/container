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
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	"github.com/alessio/shellescape"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/google/uuid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/everoute/container/model"
)

func (r *runtime) doPlatformConfig(ctx context.Context) error {
	r.setDefaultRuncPath(ctx)
	return r.enableMayDetachMounts(ctx)
}

func (r *runtime) setDefaultRuncPath(ctx context.Context) {
	// NOTE: prioritize to use containerd runc path /usr/bin/runc
	const containerdRuncPath = "/usr/bin/runc"
	err := r.execHostCommand(ctx, "check_runc_path_"+uuid.New().String(), "test", "-f", containerdRuncPath)
	if err == nil {
		r.runcPath = containerdRuncPath
	}
}

// In some version of OS, containers may not be destroyed correctly, if fs.may_detach_mounts is not set.
func (r *runtime) enableMayDetachMounts(ctx context.Context) error {
	return r.execHostCommand(ctx, "enable_fs_may_detach_mounts_"+uuid.New().String(), "sysctl", "-e", "-w", "fs.may_detach_mounts=1")
}

func (r *runtime) newTask(ctx context.Context, container containerd.Container, creator cio.Creator) (containerd.Task, error) {
	task, err := container.NewTask(ctx, creator)
	if err == nil {
		return task, nil
	}

	// task already exists return "unknown" before containerd v1.6.0, see more: https://github.com/containerd/containerd/pull/6079
	errorIsTaskExists := errdefs.IsAlreadyExists(err) ||
		errors.Is(err, errdefs.ErrUnknown) && regexp.MustCompile(`task .* already exists: unknown$`).MatchString(err.Error()) ||
		errors.Is(err, errdefs.ErrUnknown) && regexp.MustCompile(`container with id exists: .*: unknown$`).MatchString(err.Error()) ||
		errors.Is(err, errdefs.ErrUnknown) && regexp.MustCompile(`mkdir /run/containerd/io\.containerd\.runtime\.v2\.task/.*: file exists: unknown$`).MatchString(err.Error())
	if !errorIsTaskExists {
		return nil, err
	}

	// delete orphans shim on task already exists
	killCommand := fmt.Sprintf("kill -9 $(ps --no-headers -o pid,cmd -p $(pidof containerd-shim-runc-v1 containerd-shim-runc-v2) | awk %s)",
		shellescape.Quote(fmt.Sprintf(`{if ($4 == "%s" && $6 == "%s") print $1}`, r.namespace, container.ID())),
	)
	_ = r.execHostCommand(ctx, "remove-task-shim"+uuid.New().String(), "sh", "-c", killCommand)

	// delete orphans runc container in namespace
	_ = r.execHostCommand(ctx, "remove-runc-container"+uuid.New().String(), "runc", "--root="+filepath.Join("/run/containerd/runc/", r.namespace), "delete", "-f", container.ID())

	// delete orphans containerd task in namespace
	_ = r.execHostCommand(ctx, "remove-task-path"+uuid.New().String(), "rm", "-rf", filepath.Join("/run/containerd/io.containerd.runtime.v2.task/", r.namespace, container.ID()))

	// to prevent indefinitely waiting, set default timeout to 1min. If ctx
	// has an earlier deadline, the timeout will be overridden
	pollCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	// waiting for new task create
	err = wait.PollImmediateUntilWithContext(pollCtx, time.Second, func(ctx context.Context) (bool, error) {
		task, err = container.NewTask(ctx, creator)
		return err == nil, err
	})
	return task, err
}

func (r *runtime) execHostCommand(ctx context.Context, name string, commands ...string) error {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	specOpts := append(
		containerSpecOpts(r.namespace, nil, &model.Container{Name: name}),
		oci.WithHostNamespace(specs.PIDNamespace),
		oci.WithRootFSPath("rootfs"),
		oci.WithPrivileged,
		oci.WithProcessCwd("/"),
		oci.WithProcessArgs(commands...),
		withoutAnyMounts(),
		oci.WithMounts([]specs.Mount{
			{
				Type:        "rbind",
				Destination: "/",
				Source:      "/",
				Options:     []string{"rbind"},
			},
			{
				Type:        "tmpfs",
				Destination: "/dev",
				Source:      "tmpfs",
				Options:     []string{"nosuid", "strictatime", "mode=755", "size=65536k"},
			},
		}),
	)
	nc, err := r.client.NewContainer(ctx, name, withRuntime(r.runcPath, &model.Container{Name: name}), containerd.WithNewSpec(specOpts...))
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}
	defer nc.Delete(ctx)

	task, err := nc.NewTask(ctx, cio.NullIO)
	if err != nil {
		return fmt.Errorf("create task: %w", err)
	}
	return HandleTaskResult(ExecTask(ctx, task))
}
