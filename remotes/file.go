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
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sort"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/remotes"
	"github.com/docker/distribution/reference"
	ptypes "github.com/gogo/protobuf/types"
	"github.com/hashicorp/go-version"
	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
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

	URISchemeZstd = "zstd"
)

var ErrNotFound = errors.New("not found")

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
	reader, err := LookupFileInTARFile(p.file, fileLocation).Open()
	if err == nil {
		return reader, nil
	}
	if err != nil {
		// NOTE: to reproducible generate gzip from zstd, gzip header should
		// always be empty, and the default compress level should be used
		if !errors.Is(err, ErrNotFound) || len(desc.URLs) == 0 || desc.MediaType != ocispec.MediaTypeImageLayerGzip {
			return nil, err
		}
	}

	for _, downloadURL := range desc.URLs {
		u, err := url.ParseRequestURI(downloadURL)
		if err != nil {
			continue
		}

		switch u.Scheme { // //nolint: gocritic
		case URISchemeZstd:
			reader, err = LookupFileInTARFile(p.file, filepath.Join("blobs", u.Path)).Open()
			if err != nil {
				return nil, fmt.Errorf("read blobs %s: %w", u.Path, err)
			}
			greader, err := GzipReaderFromZstdUpstream(reader)
			if err != nil {
				_ = reader.Close()
				return nil, fmt.Errorf("read gzip from zstd: %w", err)
			}
			return greader, nil
		}
	}

	return nil, fmt.Errorf("digest %s not found: %w", desc.Digest, ErrNotFound)
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
					return nil, fmt.Errorf("%s not found: %w", fileName, ErrNotFound)
				}
				return nil, err
			}
			if head.Name == fileName {
				return newFileInTARFile(reader, head, tarReader)
			}
		}
	})
}

type SeekReaderAt interface {
	io.Reader
	io.Seeker
	io.ReaderAt
}

func newFileInTARFile(r io.ReadCloser, h *tar.Header, tr *tar.Reader) (io.ReadCloser, error) {
	seekReaderAt, ok := r.(SeekReaderAt)
	if !ok || h.Typeflag != tar.TypeReg {
		return struct {
			io.Reader
			io.Closer
		}{
			Reader: tr,
			Closer: r,
		}, nil
	}
	offset, err := seekReaderAt.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	return struct {
		io.Closer
		SeekReaderAt
	}{
		Closer:       r,
		SeekReaderAt: io.NewSectionReader(seekReaderAt, offset, h.Size),
	}, nil
}

func GzipReaderFromZstdUpstream(upstream io.ReadCloser) (io.ReadCloser, error) {
	zreader, err := zstd.NewReader(upstream)
	if err != nil {
		return nil, fmt.Errorf("open zstd stream: %w", err)
	}

	pr, pw := io.Pipe()
	greader := gzip.NewWriter(pw)
	go func() {
		_, err = io.Copy(greader, zreader)
		zreader.Close()
		greader.Close()
		_ = pw.CloseWithError(err)
	}()

	return struct {
		io.Reader
		io.Closer
	}{
		Reader: pr,
		Closer: multiCloser(pr, upstream),
	}, nil
}
