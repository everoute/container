/*
Copyright 2022 The Everoute Authors.

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

package remotes_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/services/version/v1"
	ptypes "github.com/gogo/protobuf/types"
	. "github.com/onsi/gomega"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"go.uber.org/goleak"
	"google.golang.org/grpc"

	"github.com/everoute/container/remotes"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestFileProviderGet(t *testing.T) {
	ctx := context.Background()

	t.Run("should get file gzip image archive format", func(t *testing.T) {
		RegisterTestingT(t)

		p := newFileProvider("testdata/example-noop-1.0.0-gzip.tar")
		image, err := p.Get(ctx, "example.com/example/noop:1.0.0")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(image.Target.Digest)).Should(Equal("sha256:cbd3ccbe91459729a64eea12be3ae561d18883b0ad1a034c0ffac5cd2ab49746"))
	})

	t.Run("should get file zstd image archive format", func(t *testing.T) {
		RegisterTestingT(t)

		p := newFileProvider("testdata/example-noop-1.0.0-zstd.tar")
		image, err := p.Get(ctx, "example.com/example/noop:1.0.0")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(image.Target.Digest)).Should(Equal("sha256:37378d19f032cd586790c085aa4f8878a6c51472740e74de16c56e5443a38f21"))
	})

	t.Run("should get file multi image archive format", func(t *testing.T) {
		t.Run("without containerd client", func(t *testing.T) {
			RegisterTestingT(t)

			p := newFileProvider("testdata/example-noop-1.0.0-multi.tar")
			image, err := p.Get(ctx, "example.com/example/noop:1.0.0")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(image.Target.Digest)).Should(Equal("sha256:cbd3ccbe91459729a64eea12be3ae561d18883b0ad1a034c0ffac5cd2ab49746"))
		})

		t.Run("with containerd version < 1.5.0", func(t *testing.T) {
			RegisterTestingT(t)

			p := newFileProvider("testdata/example-noop-1.0.0-multi.tar")
			err := p.(remotes.ContainerdClientInjectable).WithContainerdClient(ctx, &containerd.Client{})
			Expect(err).ShouldNot(HaveOccurred())

			patches := gomonkey.NewPatches()
			defer patches.Reset()
			patches.ApplyMethodFunc(version.NewVersionClient(nil), "Version", patchVersionMethod("1.4.6"))

			image, err := p.Get(ctx, "example.com/example/noop:1.0.0")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(image.Target.Digest)).Should(Equal("sha256:cbd3ccbe91459729a64eea12be3ae561d18883b0ad1a034c0ffac5cd2ab49746"))
		})

		t.Run("with containerd version >= 1.5.0", func(t *testing.T) {
			RegisterTestingT(t)

			p := newFileProvider("testdata/example-noop-1.0.0-multi.tar")
			err := p.(remotes.ContainerdClientInjectable).WithContainerdClient(ctx, &containerd.Client{})
			Expect(err).ShouldNot(HaveOccurred())

			patches := gomonkey.NewPatches()
			defer patches.Reset()
			patches.ApplyMethodFunc(version.NewVersionClient(nil), "Version", patchVersionMethod("1.5.6"))

			image, err := p.Get(ctx, "example.com/example/noop:1.0.0")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(image.Target.Digest)).Should(Equal("sha256:37378d19f032cd586790c085aa4f8878a6c51472740e74de16c56e5443a38f21"))
		})
	})
}

func TestFileProviderResolve(t *testing.T) {
	ctx := context.Background()

	t.Run("should resolve from file gzip image archive format", func(t *testing.T) {
		RegisterTestingT(t)

		p := newFileProvider("testdata/example-noop-1.0.0-gzip.tar")
		_, desc, err := p.Resolve(ctx, "example.com/example/noop:1.0.0")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(desc.Digest)).Should(Equal("sha256:cbd3ccbe91459729a64eea12be3ae561d18883b0ad1a034c0ffac5cd2ab49746"))
	})

	t.Run("should resolve from file zstd image archive format", func(t *testing.T) {
		RegisterTestingT(t)

		p := newFileProvider("testdata/example-noop-1.0.0-zstd.tar")
		_, desc, err := p.Resolve(ctx, "example.com/example/noop:1.0.0")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(desc.Digest)).Should(Equal("sha256:37378d19f032cd586790c085aa4f8878a6c51472740e74de16c56e5443a38f21"))
	})

	t.Run("should resolve from file multi image archive format", func(t *testing.T) {
		t.Run("without containerd client", func(t *testing.T) {
			RegisterTestingT(t)

			p := newFileProvider("testdata/example-noop-1.0.0-multi.tar")
			_, desc, err := p.Resolve(ctx, "example.com/example/noop:1.0.0")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(desc.Digest)).Should(Equal("sha256:cbd3ccbe91459729a64eea12be3ae561d18883b0ad1a034c0ffac5cd2ab49746"))
		})

		t.Run("with containerd version < 1.5.0", func(t *testing.T) {
			RegisterTestingT(t)

			p := newFileProvider("testdata/example-noop-1.0.0-multi.tar")
			err := p.(remotes.ContainerdClientInjectable).WithContainerdClient(ctx, &containerd.Client{})
			Expect(err).ShouldNot(HaveOccurred())

			patches := gomonkey.NewPatches()
			defer patches.Reset()
			patches.ApplyMethodFunc(version.NewVersionClient(nil), "Version", patchVersionMethod("1.4.6"))

			_, desc, err := p.Resolve(ctx, "example.com/example/noop:1.0.0")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(desc.Digest)).Should(Equal("sha256:cbd3ccbe91459729a64eea12be3ae561d18883b0ad1a034c0ffac5cd2ab49746"))
		})

		t.Run("with containerd version >= 1.5.0", func(t *testing.T) {
			RegisterTestingT(t)

			p := newFileProvider("testdata/example-noop-1.0.0-multi.tar")
			err := p.(remotes.ContainerdClientInjectable).WithContainerdClient(ctx, &containerd.Client{})
			Expect(err).ShouldNot(HaveOccurred())

			patches := gomonkey.NewPatches()
			defer patches.Reset()
			patches.ApplyMethodFunc(version.NewVersionClient(nil), "Version", patchVersionMethod("1.5.6"))

			_, desc, err := p.Resolve(ctx, "example.com/example/noop:1.0.0")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(desc.Digest)).Should(Equal("sha256:37378d19f032cd586790c085aa4f8878a6c51472740e74de16c56e5443a38f21"))
		})
	})
}

func TestFileProviderFetch(t *testing.T) {
	ctx := context.Background()

	t.Run("should fetch gzip layer from zstd blobs", func(t *testing.T) {
		RegisterTestingT(t)

		p := newFileProvider("testdata/example-noop-1.0.0-archive.tar")
		_, desc, err := p.Resolve(ctx, "example.com/example/noop:1.0.0")
		Expect(err).ShouldNot(HaveOccurred())
		Expect(string(desc.Digest)).Should(Equal("sha256:19a86a862354fd7e79a9a09287ae6aa28439049eced176d4f492a3891d4f2b52"))

		f, err := p.Fetcher(ctx, "example.com/example/noop:1.0.0")
		Expect(err).ShouldNot(HaveOccurred())
		reader, err := f.Fetch(ctx, desc)
		Expect(err).ShouldNot(HaveOccurred())

		var manifest ocispec.Manifest
		Expect(json.NewDecoder(reader).Decode(&manifest)).ShouldNot(HaveOccurred())
		Expect(reader.Close()).ShouldNot(HaveOccurred())
		Expect(manifest.Layers).Should(HaveLen(1))

		Expect(manifest.Layers[0].URLs).Should(HaveLen(1))
		reader, err = f.Fetch(ctx, manifest.Layers[0])
		Expect(err).ShouldNot(HaveOccurred())
		s := sha256.New()
		Expect(func() error { _, err = io.Copy(s, reader); return err }()).ShouldNot(HaveOccurred())
		Expect(reader.Close()).ShouldNot(HaveOccurred())
		Expect(hex.EncodeToString(s.Sum(nil))).Should(Equal(manifest.Layers[0].Digest.Encoded()))
	})
}

func newFileProvider(filePath string) remotes.StoreProvider {
	return remotes.NewFileProvider(remotes.OpenFunc(func() (io.ReadCloser, error) { return os.Open(filePath) }))
}

func patchVersionMethod(v string) func(ctx context.Context, in *ptypes.Empty, opts ...grpc.CallOption) (*version.VersionResponse, error) {
	return func(ctx context.Context, in *ptypes.Empty, opts ...grpc.CallOption) (*version.VersionResponse, error) {
		return &version.VersionResponse{Version: v}, nil
	}
}
