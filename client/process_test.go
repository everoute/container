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

package client_test

import (
	"errors"
	"testing"
	"time"

	"github.com/containerd/containerd"
	. "github.com/onsi/gomega"
	"github.com/samber/lo"

	"github.com/everoute/container/client"
)

func TestHandleTaskResult(t *testing.T) {
	RegisterTestingT(t)

	t.Run("handle normal exit task", func(t *testing.T) {
		err := client.HandleTaskResult(containerd.NewExitStatus(0, time.Now(), nil), nil)
		Expect(err).ShouldNot(HaveOccurred())
	})

	t.Run("handle task exec error", func(t *testing.T) {
		err := client.HandleTaskResult(nil, errors.New("unittest"))
		Expect(err).Should(MatchError(errors.New("unittest")))
	})

	t.Run("handle task exit error", func(t *testing.T) {
		err := client.HandleTaskResult(containerd.NewExitStatus(0, time.Now(), errors.New("unittest")), nil)
		Expect(err).Should(MatchError(errors.New("unittest")))
	})

	t.Run("handle task exit code", func(t *testing.T) {
		err := client.HandleTaskResult(containerd.NewExitStatus(10, time.Now(), nil), nil)
		Expect(err).Should(HaveOccurred())
		e, ok := lo.ErrorsAs[*client.ExitError](err)
		Expect(ok).Should(BeTrue())
		Expect(e.ExitCode).Should(Equal(uint32(10)))
	})
}
