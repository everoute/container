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
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/runtime/restart"
	jsonpatch "github.com/evanphx/json-patch"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/everoute/container/model"
	"github.com/everoute/container/remotes"
)

type runtime struct {
	platform  platforms.MatchComparer
	namespace string
	client    *containerd.Client
	resolver  remotes.Resolver
}

// Options to build a new Runtime
type Options struct {
	Endpoint  string           // containerd endpoint
	Namespace string           // containerd namespace
	TLSConfig *tls.Config      // containerd endpoint tls config
	Timeout   time.Duration    // containerd connect timeout
	Provider  remotes.Provider // containerd image provider
}

// NewRuntime create a new instance of Runtime
func NewRuntime(ctx context.Context, opt Options) (Runtime, error) {
	var client *containerd.Client
	var err error
	var platform platforms.MatchComparer

	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	// always close connection with containerd on error
	defer func() {
		if err != nil && client != nil {
			client.Close()
		}
	}()

	// get containerd client from unix socket or tcp connection
	if strings.HasPrefix(opt.Endpoint, "/") { // unix socket
		client, err = containerd.New(opt.Endpoint, containerd.WithTimeout(opt.Timeout))
	} else {
		client, err = newTCPClient(ctx, opt.Endpoint, opt.TLSConfig, opt.Timeout)
	}
	if err != nil {
		return nil, err
	}

	// get platform that the containerd support
	platform, err = client.GetSnapshotterSupportedPlatforms(ctx, containerd.DefaultSnapshotter)
	if err != nil {
		return nil, err
	}

	r := &runtime{
		platform:  platform,
		namespace: opt.Namespace,
		client:    client,
		resolver:  remotes.ProviderResolver{Provider: opt.Provider},
	}
	return r, nil
}

func newTCPClient(ctx context.Context, endpoint string, tlsConfig *tls.Config, timeout time.Duration) (*containerd.Client, error) {
	var opts = []grpc.DialOption{grpc.WithBlock()}
	if tlsConfig == nil {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}

	conn, err := grpc.DialContext(ctx, endpoint, opts...)
	if err != nil {
		return nil, err
	}

	// containerd.NewWithConn always use io.containerd.runtime.v1/linux as runtime
	// so must specify runtime(io.containerd.runc.v2) when create container.
	return containerd.NewWithConn(conn, containerd.WithTimeout(timeout))
}

func (r *runtime) ConfigRuntime(ctx context.Context) error {
	return r.doConfig(ctx)
}

func (r *runtime) ImportImages(ctx context.Context, refs ...string) error {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	for _, ref := range refs {
		_, err := r.client.Pull(ctx, ref,
			containerd.WithPlatformMatcher(r.platform),
			containerd.WithResolver(r.resolver),
			containerd.WithPullUnpack,
			containerd.WithPullSnapshotter(containerd.DefaultSnapshotter),
		)
		if err != nil {
			return fmt.Errorf("import %s: %s", ref, err)
		}
	}
	return nil
}

func (r *runtime) ListImages(ctx context.Context) ([]images.Image, error) {
	ctx = namespaces.WithNamespace(ctx, r.namespace)
	return r.client.ImageService().List(ctx)
}

func (r *runtime) RemoveImage(ctx context.Context, ref string) error {
	ctx = namespaces.WithNamespace(ctx, r.namespace)
	err := r.client.ImageService().Delete(ctx, ref, images.SynchronousDelete())
	return ignoreNotFoundError(err)
}

func (r *runtime) GetImage(ctx context.Context, ref string) (*images.Image, bool, error) {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	img, err := r.getImage(ctx, ref)
	if err != nil {
		return nil, false, ignoreNotFoundError(err)
	}

	var imgMetadata = img.Metadata()
	return &imgMetadata, true, nil
}

func (r *runtime) getImage(ctx context.Context, ref string) (containerd.Image, error) {
	i, err := r.client.ImageService().Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	return containerd.NewImageWithPlatform(r.client, i, r.platform), nil
}

func (r *runtime) CreateContainer(ctx context.Context, container *model.Container, follow bool) error {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	image, err := r.getImage(ctx, container.Image)
	if err != nil {
		return fmt.Errorf("get image %s: %s", container.Image, err)
	}

	nc, err := r.client.NewContainer(ctx, container.Name,
		containerd.WithImageName(container.Image),
		withNewSnapshotAndConfig(image, container.ConfigContent),
		withLogPath(container.Process.LogPath),
		containerd.WithRuntime(defaults.DefaultRuntime, nil),
		containerd.WithNewSpec(containerSpecOpts(r.namespace, image, container)...),
	)
	if err != nil {
		return fmt.Errorf("create container: %s", err)
	}

	task, err := r.newTask(ctx, nc, cio.LogFile(container.Process.LogPath))
	if err != nil {
		return fmt.Errorf("create task: %s", err)
	}
	defer func() {
		if err != nil || follow {
			_, _ = task.Delete(ctx, containerd.WithProcessKill)
		}
	}()

	err = task.Start(ctx)
	if err != nil {
		return err
	}

	if container.Process.RestartPolicy == model.RestartPolicyAlways {
		err = nc.Update(ctx, withLogPath(container.Process.LogPath), restart.WithStatus(containerd.Running))
		if err != nil {
			return err
		}
	}

	if follow {
		status, err := task.Wait(ctx)
		if err != nil {
			return fmt.Errorf("wait task: %s", err)
		}
		select {
		case rs := <-status:
			if rs.ExitCode() != 0 {
				return fmt.Errorf("exit with err code %d: %s", rs.ExitCode(), rs.Error())
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (r *runtime) RemoveContainer(ctx context.Context, containerID string) error {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	container, err := r.client.LoadContainer(ctx, containerID)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil
		}
		return err
	}

	_ = container.Update(ctx, func(ctx context.Context, client *containerd.Client, c *containers.Container) error {
		delete(c.Labels, restart.StatusLabel)
		return nil
	})

	task, err := container.Task(ctx, nil)
	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	if err == nil {
		_, err = task.Delete(ctx, containerd.WithProcessKill)
		if err != nil && !errdefs.IsNotFound(err) {
			return err
		}
	}

	return container.Delete(ctx, containerd.WithSnapshotCleanup)
}

func (r *runtime) GetContainer(ctx context.Context, containerID string) (*model.Container, error) {
	ctx = namespaces.WithNamespace(ctx, r.namespace)
	container, err := r.client.ContainerService().Get(ctx, containerID)
	if err != nil {
		return nil, err
	}
	return parseContainer(container)
}

func (r *runtime) ListContainers(ctx context.Context) ([]*model.Container, error) {
	ctx = namespaces.WithNamespace(ctx, r.namespace)
	cs, err := r.client.ContainerService().List(ctx)
	if err != nil {
		return nil, err
	}
	containerList := make([]*model.Container, 0, len(cs))
	for _, c := range cs {
		parsedContainer, err := parseContainer(c)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %s", c.ID, err)
		}
		containerList = append(containerList, parsedContainer)
	}
	return containerList, nil
}

func (r *runtime) RemoveNamespace(ctx context.Context) error {
	err := r.client.NamespaceService().Delete(ctx, r.namespace)
	return ignoreNotFoundError(err)
}

func (r *runtime) GetContainerStatus(ctx context.Context, containerID string) (containerd.Status, error) {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	c, err := r.client.LoadContainer(ctx, containerID)
	if err != nil {
		return containerd.Status{}, fmt.Errorf("load container: %s", err)
	}

	task, err := c.Task(ctx, nil)
	if err != nil {
		return containerd.Status{}, fmt.Errorf("load task: %s", err)
	}

	return task.Status(ctx)
}

func (r *runtime) ExecCommand(ctx context.Context, containerID string, commands []string) (*containerd.ExitStatus, error) {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	c, err := r.client.LoadContainer(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("load container: %s", err)
	}

	task, err := c.Task(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("load task: %s", err)
	}

	spec, err := c.Spec(ctx)
	if err != nil {
		return nil, fmt.Errorf("load task spec: %s", err)
	}

	taskExecID := "exec-" + rand.String(10)
	progressSpec := spec.Process
	progressSpec.Terminal = false
	progressSpec.Args = commands

	progress, err := task.Exec(ctx, taskExecID, progressSpec, cio.NullIO)
	if err != nil {
		return nil, fmt.Errorf("exec command: %s", err)
	}
	defer progress.Delete(ctx, containerd.WithProcessKill)

	err = progress.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("start progress: %s", err)
	}

	statusChan, err := progress.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("wait task: %s", err)
	}

	select {
	case exitStatus := <-statusChan:
		return &exitStatus, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *runtime) Close() error {
	return r.client.Close()
}

func (r *runtime) doConfig(ctx context.Context) error {
	if err := r.doPlatformConfig(ctx); err != nil {
		return err
	}
	return nil
}

func containerSpecOpts(namespace string, img containerd.Image, container *model.Container) []oci.SpecOpts {
	var specOpts []oci.SpecOpts
	specOpts = append(specOpts, oci.WithProcessCwd(container.Process.WorkingDir))
	specOpts = append(specOpts, oci.WithProcessArgs(container.Process.Args...))
	specOpts = append(specOpts, oci.WithCgroup(path.Join(container.CgroupParent, namespace, container.Name)))
	specOpts = append(specOpts, oci.WithEnv(container.Process.Env))
	specOpts = append(specOpts, oci.WithDefaultPathEnv)
	specOpts = append(specOpts, oci.WithMounts(container.Mounts))
	specOpts = append(specOpts, oci.WithHostname("localhost"))
	specOpts = append(specOpts, oci.WithHostNamespace(specs.NetworkNamespace), oci.WithHostHostsFile, oci.WithHostResolvconf)
	if container.Privilege {
		specOpts = append(specOpts, oci.WithPrivileged)
	}
	specOpts = append(specOpts, oci.WithAddedCapabilities(container.Capabilities))
	if img != nil {
		specOpts = append(specOpts, withImageENV(img))
	}
	if container.MemoryLimit > 0 {
		specOpts = append(specOpts, oci.WithMemoryLimit(container.MemoryLimit))
	}
	if container.CPUQuota > 0 && container.CPUPeriod > 0 {
		specOpts = append(specOpts, oci.WithCPUCFS(container.CPUQuota, container.CPUPeriod))
	}
	specOpts = append(specOpts, withRlimits(container.Rlimits))
	specOpts = append(specOpts, withSpecPatches(container.SpecPatches))
	return specOpts
}

func parseContainer(container containers.Container) (*model.Container, error) {
	spec := &specs.Spec{}

	if err := json.Unmarshal(container.Spec.Value, spec); err != nil {
		return nil, err
	}

	c := &model.Container{
		Name:   container.ID,
		Image:  container.Image,
		Mounts: spec.Mounts,
		Process: model.Process{
			Args:       spec.Process.Args,
			Env:        spec.Process.Env,
			WorkingDir: spec.Process.Cwd,
			LogPath:    container.Labels[restart.LogPathLabel],
		},
	}
	return c, nil
}

func toRawConfig(config []model.ConfigFile) []byte {
	var rawData bytes.Buffer
	tw := tar.NewWriter(&rawData)
	defer tw.Close()

	for _, file := range config {
		_ = tw.WriteHeader(&tar.Header{
			Name: file.Path,
			Size: int64(len(file.FileContent)),
			Mode: int64(file.FileMode),
		})
		_, _ = tw.Write(file.FileContent)
	}

	return rawData.Bytes()
}

func withoutAnyMounts() oci.SpecOpts {
	return func(ctx context.Context, client oci.Client, container *containers.Container, spec *oci.Spec) error {
		spec.Mounts = nil
		return nil
	}
}

func withNewSnapshotAndConfig(img containerd.Image, configContent []model.ConfigFile) containerd.NewContainerOpts {
	return func(ctx context.Context, client *containerd.Client, c *containers.Container) error {
		var (
			snapshotID = rand.String(10)
			data       = toRawConfig(configContent)
			descriptor = v1.Descriptor{
				MediaType: v1.MediaTypeImageLayer,
				Digest:    digest.SHA256.FromBytes(data),
				Size:      int64(len(data)),
			}
			ref = fmt.Sprintf("ingest-%s", descriptor.Digest)
		)

		diffIDs, err := img.RootFS(ctx)
		if err != nil {
			return err
		}

		mounts, err := client.SnapshotService(containerd.DefaultSnapshotter).Prepare(ctx, snapshotID, identity.ChainID(diffIDs).String())
		if err != nil {
			return err
		}

		err = content.WriteBlob(ctx, client.ContentStore(), ref, bytes.NewReader(data), descriptor)
		if err != nil {
			return fmt.Errorf("write config content: %s", err)
		}

		if _, err = client.DiffService().Apply(ctx, descriptor, mounts); err != nil {
			return err
		}

		c.Snapshotter = containerd.DefaultSnapshotter
		c.SnapshotKey = snapshotID
		return nil
	}
}

func withImageENV(img containerd.Image) oci.SpecOpts {
	return func(ctx context.Context, client oci.Client, c *containers.Container, s *oci.Spec) error {
		ic, err := img.Config(ctx)
		if err != nil {
			return err
		}
		var (
			ociimage v1.Image
			config   v1.ImageConfig
		)
		switch ic.MediaType {
		case v1.MediaTypeImageConfig, images.MediaTypeDockerSchema2Config:
			p, err := content.ReadBlob(ctx, img.ContentStore(), ic)
			if err != nil {
				return err
			}

			if err := json.Unmarshal(p, &ociimage); err != nil {
				return err
			}
			config = ociimage.Config
		default:
			return fmt.Errorf("unknown image config media type %s", ic.MediaType)
		}

		s.Process.Env = sets.NewString(append(config.Env, s.Process.Env...)...).List()
		return nil
	}
}

func withLogPath(logPath string) func(ctx context.Context, client *containerd.Client, c *containers.Container) error {
	return func(ctx context.Context, client *containerd.Client, c *containers.Container) error {
		if c.Labels == nil {
			c.Labels = make(map[string]string)
		}

		uri, err := cio.LogURIGenerator("file", logPath, nil)
		if err != nil {
			return err
		}

		c.Labels[restart.LogPathLabel] = logPath
		c.Labels[restart.LogURILabel] = uri.String()
		return nil
	}
}

func withRlimits(rlimits []specs.POSIXRlimit) oci.SpecOpts {
	return func(ctx context.Context, client oci.Client, container *containers.Container, spec *oci.Spec) error {
		if spec.Process == nil {
			spec.Process = &specs.Process{}
		}
		rlimitsMap := make(map[string]specs.POSIXRlimit)
		for _, rlimit := range append(spec.Process.Rlimits, rlimits...) {
			rlimitsMap[rlimit.Type] = rlimit
		}
		spec.Process.Rlimits = make([]specs.POSIXRlimit, 0, len(rlimitsMap))
		for _, rlimit := range rlimitsMap {
			spec.Process.Rlimits = append(spec.Process.Rlimits, rlimit)
		}
		return nil
	}
}

func withSpecPatches(specPatches []json.RawMessage) oci.SpecOpts {
	opts := make([]oci.SpecOpts, 0, len(specPatches))
	for _, specPatch := range specPatches {
		opts = append(opts, withSpecPatch(specPatch))
	}
	return oci.Compose(opts...)
}

func withSpecPatch(specPatch json.RawMessage) oci.SpecOpts {
	return func(ctx context.Context, client oci.Client, container *containers.Container, spec *oci.Spec) error {
		if len(specPatch) == 0 {
			return nil
		}
		patch, err := jsonpatch.DecodePatch(specPatch)
		if err != nil {
			return fmt.Errorf("invalid spec-patch(%s): %s", string(specPatch), err)
		}
		rawSpec, err := json.Marshal(spec)
		if err != nil {
			return fmt.Errorf("marshal spec as json: %s", err)
		}
		patSpec, err := patch.Apply(rawSpec)
		if err != nil {
			return fmt.Errorf("patch container spec: %s", err)
		}
		return json.Unmarshal(patSpec, spec)
	}
}

func ignoreNotFoundError(err error) error {
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}
