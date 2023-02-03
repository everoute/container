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
	"fmt"

	"github.com/alessio/shellescape"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/plugin"
	"github.com/everoute/container/model"
	"github.com/google/uuid"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func (r *runtime) doPlatformConfig(ctx context.Context) error {
	return r.enableMayDetachMounts(ctx)
}

// In some version of OS, containers may not be destroyed correctly, if fs.may_detach_mounts is not set.
func (r *runtime) enableMayDetachMounts(ctx context.Context) error {
	return r.execHostCommand(ctx, "enable_fs_may_detach_mounts_"+uuid.New().String(), "sysctl", "-e", "-w", "fs.may_detach_mounts=1")
}

func (r *runtime) newTask(ctx context.Context, container containerd.Container, creator cio.Creator) (containerd.Task, error) {
	task, err := container.NewTask(ctx, creator)
	if err == nil || !errdefs.IsAlreadyExists(err) {
		return task, err
	}

	// delete orphans shim on task already exists
	killCommand := fmt.Sprintf("kill -9 $(ps --no-headers -o pid,cmd -p $(pidof containerd-shim-runc-v1 containerd-shim-runc-v2) | awk %s)",
		shellescape.Quote(fmt.Sprintf(`{if ($4 == "%s" && $6 == "%s") print $1}`, r.namespace, container.ID())),
	)
	_ = r.execHostCommand(ctx, "remove-task-shim"+uuid.New().String(), "sh", "-c", killCommand)

	return container.NewTask(ctx, creator)
}

func (r *runtime) execHostCommand(ctx context.Context, name string, commands ...string) error {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	specOpts := append(
		containerSpecOpts(r.namespace, nil, &model.Container{Name: name}),
		oci.WithHostNamespace(specs.PIDNamespace),
		oci.WithRootFSReadonly(),
		oci.WithRootFSPath("rootfs"),
		oci.WithPrivileged,
		oci.WithProcessCwd("/"),
		oci.WithProcessArgs(commands...),
		withoutAnyMounts(),
		oci.WithMounts([]specs.Mount{{Type: "rbind", Destination: "/", Source: "/", Options: []string{"rbind", "ro"}}}),
	)
	nc, err := r.client.NewContainer(ctx, name, containerd.WithRuntime(plugin.RuntimeRuncV2, nil), containerd.WithNewSpec(specOpts...))
	if err != nil {
		return fmt.Errorf("create container: %s", err)
	}
	defer nc.Delete(ctx)

	task, err := nc.NewTask(ctx, cio.NullIO)
	if err != nil {
		return fmt.Errorf("create task: %s", err)
	}
	defer task.Delete(ctx, containerd.WithProcessKill)

	if err = task.Start(ctx); err != nil {
		return fmt.Errorf("start task: %s", err)
	}

	status, _ := task.Wait(ctx)
	select {
	case <-ctx.Done():
		return fmt.Errorf("context done: %s", ctx.Err())
	case rs := <-status:
		if rs.Error() != nil {
			return fmt.Errorf("unexpected error: %s", rs.Error())
		}
		if rs.ExitCode() != 0 {
			return fmt.Errorf("task exit with rc = %d", rs.ExitCode())
		}
		return nil
	}
}
