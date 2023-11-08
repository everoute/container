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
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/remotes"
	"github.com/docker/distribution/reference"
	ptypes "github.com/gogo/protobuf/types"
	"github.com/hashicorp/go-version"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// File provides an abstraction for anything like a file
type File interface {
	Open() (io.ReadCloser, error)
}

// OpenFunc implements File
type OpenFunc func() (io.ReadCloser, error)

func (f OpenFunc) Open() (io.ReadCloser, error) { return f() }

const (
	// AnnotationImageArchiveType is the annotation key for the image archive type
	AnnotationImageArchiveType = "io.everoute.image.archive-type"

	ImageArchiveTypeGzip = ocispec.MediaTypeImageLayerGzip
	ImageArchiveTypeZstd = ocispec.MediaTypeImageLayerZstd
)

// NewFileProvider create a new file provider
func NewFileProvider(file File) StoreProvider {
	return &fileProvider{
		file: file,
	}
}

// fileProvider provide image from the image tar file
// for now only supports oci image layout 1.0.0:
// - https://github.com/opencontainers/image-spec/blob/main/image-layout.md
type fileProvider struct {
	file   File
	client *containerd.Client
}

func (p *fileProvider) Name() string { return "file provider" }

func (p *fileProvider) WithContainerdClient(ctx context.Context, client *containerd.Client) error {
	p.client = client
	return nil
}

func (p *fileProvider) Resolve(ctx context.Context, ref string) (string, ocispec.Descriptor, error) {
	image, err := p.Get(ctx, ref)
	return image.Name, image.Target, err
}

func (p *fileProvider) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	if _, _, err := p.Resolve(ctx, ref); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *fileProvider) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	fileLocation := fmt.Sprintf("blobs/%s/%s", desc.Digest.Algorithm(), desc.Digest.Encoded())
	return LookupFileInTARFile(p.file, fileLocation).Open()
}

func (p *fileProvider) Get(ctx context.Context, ref string) (images.Image, error) {
	imageList, err := p.List(ctx)
	if err != nil {
		return images.Image{}, fmt.Errorf("list images from file: %w", err)
	}

	for _, image := range imageList {
		if image.Name == ref {
			return image, nil
		}
	}

	return images.Image{}, fmt.Errorf("image with reference %s not found", ref)
}

func (p *fileProvider) List(ctx context.Context) ([]images.Image, error) {
	if err := p.checkImageLayout(); err != nil {
		return nil, err
	}

	reader, err := LookupFileInTARFile(p.file, "index.json").Open()
	if err != nil {
		return nil, fmt.Errorf("open file: %s", err)
	}
	defer reader.Close()

	var index ocispec.Index
	if err = json.NewDecoder(reader).Decode(&index); err != nil {
		return nil, fmt.Errorf("decode index: %s", err)
	}

	imagesMap := make(map[string][]images.Image, len(index.Manifests))
	for _, manifest := range index.Manifests {
		imageName := ImageNameFromManifest(manifest)
		if imageName != "" {
			imagesMap[imageName] = append(imagesMap[imageName], images.Image{Name: imageName, Target: manifest})
		}
	}
	return p.selectImagesFromMap(ctx, imagesMap)
}

func (p *fileProvider) checkImageLayout() error {
	reader, err := LookupFileInTARFile(p.file, ocispec.ImageLayoutFile).Open()
	if err != nil {
		return fmt.Errorf("open file: %s", err)
	}
	defer reader.Close()

	var imageLayout ocispec.ImageLayout
	if err = json.NewDecoder(reader).Decode(&imageLayout); err != nil {
		return fmt.Errorf("decode layout: %s", err)
	}
	if imageLayout.Version != ocispec.ImageLayoutVersion {
		return fmt.Errorf("unsupport layout version %s", imageLayout.Version)
	}
	return nil
}

func (p *fileProvider) selectImagesFromMap(ctx context.Context, imagesMap map[string][]images.Image) ([]images.Image, error) {
	var supportArchiveTypeZstd bool
	var imageList []images.Image

	if p.client != nil {
		response, err := p.client.VersionService().Version(ctx, &ptypes.Empty{})
		if err != nil {
			return nil, fmt.Errorf("probe containerd version: %w", err)
		}
		// NOTE: containerd support zstd since version 1.5.0
		cv, ve := version.NewVersion(response.Version)
		supportArchiveTypeZstd = ve == nil && cv.GreaterThanOrEqual(version.Must(version.NewVersion("1.5.0")))
	}

	for _, targetImages := range imagesMap {
		if len(targetImages) == 0 {
			continue
		}
		sort.Slice(targetImages, func(i, j int) bool {
			getImageArchiveType := func(image images.Image) int {
				switch image.Target.Annotations[AnnotationImageArchiveType] {
				case ImageArchiveTypeZstd:
					return 2 // zstd
				case ImageArchiveTypeGzip:
					return 0 // gzip
				default:
					return 1 // unknown
				}
			}
			return supportArchiveTypeZstd != (getImageArchiveType(targetImages[i]) < getImageArchiveType(targetImages[j]))
		})
		imageList = append(imageList, targetImages[0])
	}

	return imageList, nil
}

func ImageNameFromManifest(manifest ocispec.Descriptor) string {
	if manifest.Annotations == nil {
		return ""
	}

	imageName := manifest.Annotations[images.AnnotationImageName]
	if _, err := reference.Parse(imageName); err == nil {
		return imageName
	}

	imageName = manifest.Annotations[ocispec.AnnotationRefName]
	if _, err := reference.Parse(imageName); err == nil {
		return imageName
	}

	return ""
}

func LookupFileInTARFile(file File, fileName string) File {
	return OpenFunc(func() (io.ReadCloser, error) {
		reader, err := file.Open()
		if err != nil {
			return nil, err
		}
		tarReader := tar.NewReader(reader)

		for {
			head, err := tarReader.Next()
			if err != nil {
				reader.Close()
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
					Closer: reader,
				}, nil
			}
		}
	})
}
