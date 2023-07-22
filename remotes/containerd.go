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

package remotes

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// NewContainerdProvider create a new containerd provider
func NewContainerdProvider(endpoint, namespace string) Provider {
	return &containerdProvider{
		endpoint:  endpoint,
		namespace: namespace,
		timeout:   2 * time.Second,
	}
}

// containerdProvider provide image from content
type containerdProvider struct {
	endpoint  string
	namespace string
	timeout   time.Duration
}

func (c *containerdProvider) Name() string { return "containerd provider" }

func (c *containerdProvider) Resolve(ctx context.Context, ref string) (name string, desc ocispec.Descriptor, err error) {
	err = c.executeOnContainerd(ctx, true, func(ctx context.Context, client *containerd.Client) error {
		image, err := client.ImageService().Get(ctx, ref)
		if err != nil {
			return err
		}

		name = image.Name
		desc = image.Target
		return nil
	})

	return name, desc, err
}

func (c *containerdProvider) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	if _, _, err := c.Resolve(ctx, ref); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *containerdProvider) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	var readCloser io.ReadCloser

	err := c.executeOnContainerd(ctx, false, func(ctx context.Context, client *containerd.Client) error {
		readerAt, err := client.ContentStore().ReaderAt(ctx, desc)
		if err != nil {
			_ = client.Close()
			return err
		}

		readCloser = struct {
			io.Reader
			io.Closer
		}{
			Reader: io.NewSectionReader(readerAt, 0, desc.Size),
			Closer: multiCloser(readerAt, client),
		}
		return nil
	})

	return readCloser, err
}

type executeFunc func(ctx context.Context, client *containerd.Client) error

func (c *containerdProvider) executeOnContainerd(ctx context.Context, close bool, f executeFunc) error {
	client, err := containerd.New(c.endpoint, containerd.WithTimeout(c.timeout))
	if err != nil {
		return fmt.Errorf("connect to %s: %s", c.endpoint, err)
	}

	if close {
		defer client.Close()
	}

	ctx = namespaces.WithNamespace(ctx, c.namespace)
	return f(ctx, client)
}

func multiCloser(closers ...io.Closer) io.Closer {
	return closeFunc(func() error {
		for _, closer := range closers {
			if err := closer.Close(); err != nil {
				return err
			}
		}
		return nil
	})
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }
