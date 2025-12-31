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

package remotes_test

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/klauspost/compress/gzip"
	. "github.com/onsi/gomega"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/samber/lo"

	"github.com/everoute/container/remotes"
)

func TestDownloadGZIPFromZSTD(t *testing.T) {
	RegisterTestingT(t)

	ctx := context.Background()
	f := remotes.OpenFunc(func() (io.ReadCloser, error) { return os.Open("testdata/example-zstd.tar") })
	d := remotes.NewDownloadGZIPFromZSTD(f)

	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		URLs: []string{
			"https://example.com/blob/b867a7a339c983abc0a33b8f7da12380ec7cec3f2a1e6ba80ec7cb",
			"zstd:///sha256/d1b7ce66ba6cbfd27bf4adf2554e2e999689820ee37176138843f60f502bf47f",
		},
	}
	Expect(d.Support(ctx, desc, desc.URLs[1])).Should(BeTrue())
	Expect(d.Support(ctx, desc, desc.URLs[0])).Should(BeFalse())

	cr, err := d.Download(ctx, desc, desc.URLs[1])
	Expect(err).ShouldNot(HaveOccurred())
	defer cr.Close()
	gr, err := gzip.NewReader(cr)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(string(lo.Must(io.ReadAll(gr)))).Should(Equal("HELLO WORLD"))
	Expect(gr.Close()).ShouldNot(HaveOccurred())
	Expect(cr.Close()).ShouldNot(HaveOccurred())

	cr, err = remotes.DownloadFetch(ctx, d, desc)
	Expect(err).ShouldNot(HaveOccurred())
	Expect(cr.Close()).ShouldNot(HaveOccurred())
}
