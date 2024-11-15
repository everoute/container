/*
Copyright 2024 The Everoute Authors.

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
	"time"

	"github.com/containerd/containerd"
)

func ExecTask(ctx context.Context, task containerd.Process) (*containerd.ExitStatus, error) {
	defer task.Delete(ctx, containerd.WithProcessKill)

	err := task.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("task start %s: %w", task.ID(), err)
	}
	return WaitTask(ctx, task)
}

func WaitTask(ctx context.Context, task containerd.Process) (*containerd.ExitStatus, error) {
	status, err := task.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("task wait %s: %w", task.ID(), err)
	}

	select {
	case ts := <-status:
		return &ts, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("timeout waiting result: %w", ctx.Err())
	}
}

type ExitError struct {
	ExitCode uint32
	ExitTime time.Time
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("task exit %d on %s", e.ExitCode, e.ExitTime)
}

func HandleTaskResult(status *containerd.ExitStatus, err error) error {
	if err != nil {
		return err
	}
	if status.Error() != nil {
		return status.Error()
	}
	if status.ExitCode() != 0 {
		return &ExitError{ExitCode: status.ExitCode(), ExitTime: status.ExitTime()}
	}
	return nil
}
