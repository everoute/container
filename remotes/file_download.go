/*
Copyright 2025 The Everoute Authors.

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
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/url"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Downloader interface {
	Support(ctx context.Context, desc ocispec.Descriptor, downloadURL string) bool
	Download(ctx context.Context, desc ocispec.Descriptor, downloadURL string) (io.ReadCloser, error)
}

func DownloadFetch(ctx context.Context, d Downloader, desc ocispec.Descriptor) (io.ReadCloser, error) {
	for _, downloadURL := range desc.URLs {
		if d.Support(ctx, desc, downloadURL) {
			return d.Download(ctx, desc, downloadURL)
		}
	}
	return nil, fmt.Errorf("digest %s not found: %w", desc.Digest, ErrNotFound)
}

func NewDownloadGZIPFromZSDT(f File) Downloader {
	return &downloadGZIPFromZSDT{file: f}
}

type downloadGZIPFromZSDT struct {
	file File
}

func (d *downloadGZIPFromZSDT) Support(_ context.Context, desc ocispec.Descriptor, downloadURL string) bool {
	// NOTE: to reproducible generate gzip from zstd, gzip header should
	// always be empty, and the default compress level should be used
	u, err := url.ParseRequestURI(downloadURL)
	return err == nil && u.Scheme == URISchemeZstd && desc.MediaType == ocispec.MediaTypeImageLayerGzip
}

func (d *downloadGZIPFromZSDT) Download(_ context.Context, _ ocispec.Descriptor, downloadURL string) (io.ReadCloser, error) {
	u, err := url.ParseRequestURI(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url %s: %w", downloadURL, err)
	}
	r, err := LookupFileInTARFile(d.file, filepath.Join("blobs", u.Path)).Open()
	if err != nil {
		return nil, fmt.Errorf("read blobs %s: %w", u.Path, err)
	}
	gr, err := GzipReaderFromZstdUpstream(r)
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("read gzip from zstd: %w", err)
	}
	return gr, nil
}

func GzipReaderFromZstdUpstream(upstream io.ReadCloser) (io.ReadCloser, error) {
	zr, err := zstd.NewReader(upstream)
	if err != nil {
		return nil, fmt.Errorf("open zstd stream: %w", err)
	}

	pr, pw := io.Pipe()
	gr := gzip.NewWriter(pw)
	go func() {
		_, err = io.Copy(gr, zr)
		zr.Close()
		_ = gr.Close()
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
