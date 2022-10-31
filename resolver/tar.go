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

package resolver

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// NewReadCloserFunc get an image file's ReadCloser
type NewReadCloserFunc func() (io.ReadCloser, error)

// NewReadCloserFromFile use open file as NewReadCloserFunc
func NewReadCloserFromFile(name string) NewReadCloserFunc {
	return func() (io.ReadCloser, error) {
		return os.Open(name)
	}
}

// tarFileResolver implements remotes.Resolver
// It considers an images tar as an image registry, and resolve from the tar.
// It support oci image layout 1.0.0 only.
type tarFileResolver struct {
	newReadCloser NewReadCloserFunc
}

func NewTarFileResolver(newReadCloser NewReadCloserFunc) (remotes.Resolver, error) {
	readCloser, err := findFileInReadCloser(newReadCloser, ocispec.ImageLayoutFile)
	if err != nil {
		return nil, fmt.Errorf("open image reader: %s", err)
	}
	defer readCloser.Close()

	var imageLayout ocispec.ImageLayout
	if err = json.NewDecoder(readCloser).Decode(&imageLayout); err != nil {
		return nil, fmt.Errorf("decode layout: %s", err)
	}
	if imageLayout.Version != ocispec.ImageLayoutVersion {
		return nil, fmt.Errorf("not support image layout version %s", imageLayout.Version)
	}

	return &tarFileResolver{newReadCloser: newReadCloser}, nil
}

func (t *tarFileResolver) Resolve(_ context.Context, ref string) (name string, desc ocispec.Descriptor, err error) {
	readCloser, err := findFileInReadCloser(t.newReadCloser, "index.json")
	if err != nil {
		return "", ocispec.Descriptor{}, fmt.Errorf("open image reader: %s", err)
	}
	defer readCloser.Close()

	var index ocispec.Index
	if err = json.NewDecoder(readCloser).Decode(&index); err != nil {
		return "", ocispec.Descriptor{}, fmt.Errorf("decode index: %s", err)
	}

	for _, manifest := range index.Manifests {
		if manifest.Annotations != nil &&
			(manifest.Annotations[images.AnnotationImageName] == ref || manifest.Annotations[ocispec.AnnotationRefName] == ref) {
			return ref, manifest, nil
		}
	}
	return "", ocispec.Descriptor{}, fmt.Errorf("image with reference %s not found", ref)
}

func (t *tarFileResolver) Fetcher(_ context.Context, _ string) (remotes.Fetcher, error) {
	return remotes.FetcherFunc(func(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
		// fileLocation follow https://github.com/opencontainers/image-spec/blob/main/image-layout.md
		var fileLocation = fmt.Sprintf("blobs/%s/%s", desc.Digest.Algorithm(), desc.Digest.Encoded())
		return findFileInReadCloser(t.newReadCloser, fileLocation)
	}), nil
}

func (t *tarFileResolver) Pusher(_ context.Context, _ string) (remotes.Pusher, error) {
	return nil, fmt.Errorf("pusher not implemented by tarFileResolver")
}

func findFileInReadCloser(newReadCloser NewReadCloserFunc, fileName string) (io.ReadCloser, error) {
	fileReadCloser, err := newReadCloser()
	if err != nil {
		return nil, err
	}
	tarReader := tar.NewReader(fileReadCloser)

	for {
		head, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("%s not found", fileName)
			}
			return nil, err
		}
		if head.Name == fileName {
			return struct {
				io.Reader
				io.Closer
			}{
				Reader: tarReader,
				Closer: fileReadCloser,
			}, nil
		}
	}
}
