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

	"github.com/alessio/shellescape"
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
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/runtime/restart"
	"github.com/google/uuid"
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
	"github.com/everoute/container/resolver"
)

type runtime struct {
	platform  platforms.MatchComparer
	namespace string
	client    *containerd.Client
}

func NewRuntime(endpoint string, tlsConfig *tls.Config, timeout time.Duration, namespace string) (Runtime, error) {
	var client *containerd.Client
	var err error
	var platform platforms.MatchComparer

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// always close connection with containerd on error
	defer func() {
		if err != nil && client != nil {
			client.Close()
		}
	}()

	// get containerd client from unix socket or tcp connection
	if strings.HasPrefix(endpoint, "/") { // unix socket
		client, err = containerd.New(endpoint, containerd.WithTimeout(timeout))
	} else {
		client, err = newTCPClient(ctx, endpoint, tlsConfig, timeout)
	}
	if err != nil {
		return nil, err
	}

	// get platform that the containerd support
	platform, err = client.GetSnapshotterSupportedPlatforms(ctx, containerd.DefaultSnapshotter)
	if err != nil {
		return nil, err
	}

	r := &runtime{platform: platform, namespace: namespace, client: client}
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

func (r *runtime) ImportImage(ctx context.Context, newReadCloserFunc resolver.NewReadCloserFunc, imageRefs ...string) error {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	tarResolver, err := resolver.NewTarFileResolver(newReadCloserFunc)
	if err != nil {
		// resolver.NewTarFileResolver only support oci 1.0.0 layout, to support docker layout, we need load all images
		return loadDockerLayoutImage(ctx, r.client, newReadCloserFunc)
	}

	for _, imageRef := range imageRefs {
		_, err := r.client.Pull(ctx, imageRef,
			containerd.WithPlatformMatcher(r.platform),
			containerd.WithResolver(tarResolver),
			containerd.WithPullUnpack,
			containerd.WithPullSnapshotter(containerd.DefaultSnapshotter),
		)
		if err != nil {
			return fmt.Errorf("load %s: %s", imageRef, err)
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
		restart.WithLogPath(container.Process.LogPath),
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
		err = nc.Update(ctx, restart.WithLogPath(container.Process.LogPath), restart.WithStatus(containerd.Running))
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

func (r *runtime) newTask(ctx context.Context, container containerd.Container, creator cio.Creator) (containerd.Task, error) {
	task, err := container.NewTask(ctx, creator)
	if err == nil || !errdefs.IsAlreadyExists(err) {
		return task, err
	}

	// delete orphans shim on task already exists
	killCommand := fmt.Sprintf("kill -9 $(ps --no-headers -o pid,cmd -p $(pidof containerd-shim-runc-v1 containerd-shim-runc-v2) | awk %s)",
		shellescape.Quote(fmt.Sprintf(`{if ($4 == "%s" && $6 == "%s") print $1}`, r.namespace, container.ID())),
	)
	_ = r.execHostCommand(ctx, "remove-task-shim"+uuid.New().String(), "sh", "-c", killCommand)

	return container.NewTask(ctx, creator)
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
		if err != nil {
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

func (r *runtime) execHostCommand(ctx context.Context, name string, commands ...string) error {
	ctx = namespaces.WithNamespace(ctx, r.namespace)

	specOpts := append(
		containerSpecOpts(r.namespace, nil, &model.Container{Name: name}),
		oci.WithHostNamespace(specs.PIDNamespace),
		oci.WithRootFSReadonly(),
		oci.WithRootFSPath("rootfs"),
		oci.WithPrivileged,
		oci.WithProcessCwd("/"),
		oci.WithProcessArgs(commands...),
		withoutAnyMounts(),
		oci.WithMounts([]specs.Mount{{Type: "rbind", Destination: "/", Source: "/", Options: []string{"rbind", "ro"}}}),
	)
	nc, err := r.client.NewContainer(ctx, name, containerd.WithRuntime(plugin.RuntimeRuncV2, nil), containerd.WithNewSpec(specOpts...))
	if err != nil {
		return fmt.Errorf("create container: %s", err)
	}
	defer nc.Delete(ctx)

	task, err := nc.NewTask(ctx, cio.NullIO)
	if err != nil {
		return fmt.Errorf("create task: %s", err)
	}
	defer task.Delete(ctx, containerd.WithProcessKill)

	if err = task.Start(ctx); err != nil {
		return fmt.Errorf("start task: %s", err)
	}

	status, _ := task.Wait(ctx)
	select {
	case <-ctx.Done():
		return fmt.Errorf("context done: %s", ctx.Err())
	case rs := <-status:
		if rs.Error() != nil {
			return fmt.Errorf("unexpected error: %s", rs.Error())
		}
		if rs.ExitCode() != 0 {
			return fmt.Errorf("task exit with rc = %d", rs.ExitCode())
		}
		return nil
	}
}

func loadDockerLayoutImage(ctx context.Context, client *containerd.Client, newReadCloserFunc resolver.NewReadCloserFunc) error {
	readCloser, err := newReadCloserFunc()
	if err != nil {
		return err
	}
	defer readCloser.Close()

	imgs, err := client.Import(ctx, readCloser, containerd.WithAllPlatforms(true))
	if err != nil {
		return err
	}

	for _, img := range imgs {
		err = containerd.NewImage(client, img).Unpack(ctx, containerd.DefaultSnapshotter)
		if err != nil {
			return err
		}
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
	specOpts = append(specOpts, oci.WithAddedCapabilities(container.Capabilities))
	if container.Privilege {
		specOpts = append(specOpts, oci.WithPrivileged)
	}
	if img != nil {
		specOpts = append(specOpts, withImageENV(img))
	}
	if container.MemoryLimit > 0 {
		specOpts = append(specOpts, oci.WithMemoryLimit(container.MemoryLimit))
	}
	if container.CPUQuota > 0 && container.CPUPeriod > 0 {
		specOpts = append(specOpts, oci.WithCPUCFS(container.CPUQuota, container.CPUPeriod))
	}
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

func ignoreNotFoundError(err error) error {
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}
