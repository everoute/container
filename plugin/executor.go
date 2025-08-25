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

package plugin

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	gosync "sync"
	"time"

	"github.com/containerd/containerd"
	nsapi "github.com/containerd/containerd/api/services/namespaces/v1"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/leases"
	"github.com/containerd/containerd/namespaces"
	"github.com/gogo/protobuf/types"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"github.com/everoute/container/client"
	"github.com/everoute/container/logging"
	"github.com/everoute/container/metrics"
	"github.com/everoute/container/model"
	"github.com/everoute/container/sync"
)

type Executor interface {
	io.Closer

	Precheck(ctx context.Context) error
	Apply(ctx context.Context) error
	Remove(ctx context.Context) error
	HealthProbe(ctx context.Context) *model.PluginInstanceHealthResult
}

// New create a new instance of Executor
func New(runtime client.Runtime, instance *model.PluginInstanceDefinition, opts ...ExecutorOpt) Executor {
	executor := &executor{
		instance: instance,
		runtime:  runtime,
	}
	for _, opt := range opts {
		opt(runtime, instance, executor)
	}
	return &errorWrapExecutor{
		executor:    executor,
		errorPrefix: executor.logPrefix,
	}
}

// ExecutorOpt allows callers to set options on the executor
type ExecutorOpt func(runtime client.Runtime, instance *model.PluginInstanceDefinition, w *executor)

func WithLogPrefix(logPrefix string) ExecutorOpt {
	return func(runtime client.Runtime, instance *model.PluginInstanceDefinition, w *executor) {
		w.logPrefix = logPrefix
	}
}

func WithPluginLogging(factory logging.Factory) ExecutorOpt {
	return func(runtime client.Runtime, instance *model.PluginInstanceDefinition, w *executor) {
		w.logging = factory.ProviderFor(runtime, instance)
	}
}

func WithPluginMetrics(factory metrics.Factory) ExecutorOpt {
	return func(runtime client.Runtime, instance *model.PluginInstanceDefinition, w *executor) {
		w.metrics = factory.ProviderFor(runtime, instance)
	}
}

type executor struct {
	instance  *model.PluginInstanceDefinition
	logPrefix string
	runtime   client.Runtime
	logging   logging.Provider
	metrics   metrics.Provider
}

func (w *executor) Close() error {
	return w.runtime.Close()
}

func (w *executor) Infof(format string, args ...interface{}) {
	klog.Infof(w.logPrefix+": "+format, args...)
}

func (w *executor) Warningf(format string, args ...interface{}) {
	klog.Warningf(w.logPrefix+": "+format, args...)
}

// Precheck check the environment, perform the following steps:
// 1. remove outdated precheck_containers in namespace.
// 2. upload precheck_containers required images to containerd.
// 3. start and wait precheck_containers, kill the container after timeout.
func (w *executor) Precheck(ctx context.Context) error {
	if len(w.instance.PrecheckContainers) == 0 {
		return nil
	}

	err := w.removeContainersInNamespace(ctx, w.instance.PrecheckContainers...)
	if err != nil {
		return fmt.Errorf("remove precheck containers: %s", err)
	}

	err = w.uploadContainerImages(ctx, w.instance.PrecheckContainers...)
	if err != nil {
		return fmt.Errorf("upload precheck images: %s", err)
	}

	err = w.runAndWaitContainers(ctx, w.instance.PrecheckContainers...)
	if err != nil {
		return fmt.Errorf("start precheck containers: %s", err)
	}

	w.Infof("precheck the environment has been successfully done")
	return nil
}

const (
	NamespaceLabelPluginHash            = "everoute.io/cpm/plugin-hash"
	NamespaceLabelPluginUpdateTimestamp = "everoute.io/cpm/plugin-update-timestamp"
)

// Apply installs plugin to containerd, perform the following steps:
// 1. check should skip update plugin instance.
// 2. remove operation metadata labels from containerd namespace.
// 3. config container runtime.
// 4. upload required images to containerd.
// 5. remove all containers in the containerd namespace.
// 6. start and wait init_containers, kill the container after timeout.
// 7. start and run containers.
// 8. wait for all containers ready.
// 9. setup container logging config.
// 10. setup container metrics config.
// 11. start and wait post_containers, kill the container after timeout.
// 12. remove unused images from containerd.
// 13. update operation metadata labels into containerd namespace.
func (w *executor) Apply(ctx context.Context) error {
	skip, err := w.needSkipApplyPlugin(ctx)
	if skip || err != nil {
		return err
	}

	err = w.removeOperationMetadata(ctx)
	if err != nil {
		return fmt.Errorf("remove operation metadata: %w", err)
	}

	err = w.configContainerRuntime(ctx)
	if err != nil {
		return fmt.Errorf("config container runtime: %s", err)
	}

	err = w.uploadContainerImages(ctx, append(append(w.instance.InitContainers, w.instance.Containers...), w.instance.PostContainers...)...)
	if err != nil {
		return fmt.Errorf("upload container images: %s", err)
	}

	err = w.removeContainersInNamespace(ctx)
	if err != nil {
		return fmt.Errorf("remove containers: %s", err)
	}

	err = w.runAndWaitContainers(ctx, w.instance.InitContainers...)
	if err != nil {
		return fmt.Errorf("start init containers: %s", err)
	}

	err = w.startContainers(ctx, w.instance.Containers...)
	if err != nil {
		return fmt.Errorf("start workload containers: %s", err)
	}

	err = w.waitContainersReady(ctx, w.instance.Containers...)
	if err != nil {
		return fmt.Errorf("wait for containers ready: %s", err)
	}

	err = w.setupLogging(ctx)
	if err != nil {
		return fmt.Errorf("setup logging: %s", err)
	}

	err = w.setupMetrics(ctx)
	if err != nil {
		return fmt.Errorf("setup metrics: %s", err)
	}

	err = w.runAndWaitContainers(ctx, w.instance.PostContainers...)
	if err != nil {
		return fmt.Errorf("start post containers: %s", err)
	}

	err = w.removeUnusedImages(ctx, w.instance.Containers...)
	if err != nil {
		return fmt.Errorf("remove unused images: %s", err)
	}

	err = w.updateOperationMetadata(ctx)
	if err != nil {
		return fmt.Errorf("update operation metadata: %w", err)
	}

	w.Infof("apply plugin instance has been successfully done")
	return nil
}

// Remove removes plugin from containerd, perform the following steps:
// 1. check if the namespace has been removed.
// 2. remove operation metadata labels from containerd namespace.
// 3. remove container logging config.
// 4. upload clean_containers required images to containerd.
// 5. remove all containers in the containerd namespace.
// 6. start and wait clean_containers, kill the container after timeout.
// 7. remove all containers and images in the namespace.
// 8. remove the namespace from containerd.
func (w *executor) Remove(ctx context.Context) error {
	exist, err := namespaceExists(ctx, w.runtime)
	if err == nil && !exist {
		// do nothing on remove when namespace not exist
		return nil
	}

	err = w.removeOperationMetadata(ctx)
	if err != nil {
		return fmt.Errorf("remove operation metadata: %w", err)
	}

	err = w.removeLogging(ctx)
	if err != nil {
		return fmt.Errorf("remove logging: %s", err)
	}

	err = w.removeMetrics(ctx)
	if err != nil {
		return fmt.Errorf("remove metrics: %s", err)
	}

	err = w.removeContainersInNamespace(ctx)
	if err != nil {
		return fmt.Errorf("remove containers: %s", err)
	}

	if len(w.instance.CleanContainers) != 0 {
		err = w.uploadContainerImages(ctx, w.instance.CleanContainers...)
		if err != nil {
			return fmt.Errorf("upload cleanup images: %s", err)
		}

		err = w.runAndWaitContainers(ctx, w.instance.CleanContainers...)
		if err != nil {
			return fmt.Errorf("start clean containers: %s", err)
		}
	}

	err = w.removeAllInNamespace(ctx)
	if err != nil {
		return fmt.Errorf("remove resources: %s", err)
	}

	err = w.runtime.RemoveNamespace(ctx)
	if err != nil {
		w.Warningf("failed to remove namespace: %s", err)
	}

	w.Infof("remove plugin instance has been successfully done")
	return nil
}

// HealthProbe check the plugin containers health
func (w *executor) HealthProbe(ctx context.Context) *model.PluginInstanceHealthResult {
	result := &model.PluginInstanceHealthResult{
		Healthy:             true,
		LastHealthCheckTime: time.Now(),
	}
	group := sync.NewGroup(0)
	resultUpdateLock := gosync.Mutex{}

	for _, container := range w.instance.Containers {
		containerName := container.Name
		probe := w.loadContainerProbe(container.LivenessProbe)

		group.Go(func() error {
			err := w.doCheck(ctx, containerName, probe)
			if err != nil {
				resultUpdateLock.Lock()
				result.Healthy = false
				result.UnHealthContainers = append(result.UnHealthContainers, containerName)
				resultUpdateLock.Unlock()
			}
			return err
		})
	}

	if err := group.WaitResult(); err != nil {
		result.UnHealthReason = err.Error()
	}

	return result
}

func (w *executor) needSkipApplyPlugin(ctx context.Context) (bool, error) {
	if !GetSkipNoChange(ctx) {
		return false, nil
	}

	lbs, err := namespaceLabels(ctx, w.runtime)
	if err != nil {
		return false, fmt.Errorf("namespace info: %w", err)
	}
	timestamp := time.Unix(lo.T2(strconv.ParseInt(lbs[NamespaceLabelPluginUpdateTimestamp], 10, 64)).A, 0)
	historyHash := lbs[NamespaceLabelPluginHash]
	currentHash := fmt.Sprintf("%x", sha1.Sum(lo.Must(yaml.Marshal(w.instance))))
	if timestamp.Equal(time.Time{}) ||
		time.Since(timestamp) < 0 ||
		historyHash == "" ||
		historyHash != currentHash {
		return false, nil
	}

	for _, c := range w.instance.Containers {
		status, err := w.runtime.GetContainerStatus(ctx, c.Name)
		if err != nil {
			return false, fmt.Errorf("fetch container %s status: %w", c.Name, err)
		}
		if status.Status.Status != containerd.Running ||
			status.UpdatedAt.Truncate(time.Second).After(timestamp) {
			return false, nil
		}
	}

	w.Infof("skip plugin apply becauseof no changes since the last update")
	return true, nil
}

func (w *executor) configContainerRuntime(ctx context.Context) error {
	w.Infof("config container runtime")
	return w.runtime.ConfigRuntime(ctx)
}

func (w *executor) uploadContainerImages(ctx context.Context, containers ...model.ContainerDefinition) error {
	imageRefs := sets.NewString()
	for _, c := range containers {
		imageRefs.Insert(c.Image)
	}
	w.Infof("uploading images to containerd: %v", imageRefs.List())
	return w.runtime.ImportImages(ctx, imageRefs.List()...)
}

func (w *executor) removeContainersInNamespace(ctx context.Context, containers ...model.ContainerDefinition) error {
	var containersToRemove []string

	if len(containers) == 0 { // remove all containers on containerd
		cs, err := w.runtime.ListContainers(ctx)
		if err != nil {
			return err
		}
		for _, c := range cs {
			containersToRemove = append(containersToRemove, c.Name)
		}
	} else {
		for _, c := range containers {
			containersToRemove = append(containersToRemove, c.Name)
		}
	}

	for _, c := range containersToRemove {
		w.Infof("remove container %s from containerd", c)
		if err := w.runtime.RemoveContainer(ctx, c); err != nil {
			return err
		}
	}

	return nil
}

func (w *executor) runAndWaitContainers(ctx context.Context, containers ...model.ContainerDefinition) error {
	for item := range containers {
		// fix: Implicit memory aliasing in for loop
		c := containers[item]
		w.Infof("start and wait container %s", c.Name)
		err := w.runtime.CreateContainer(ctx, toRuntimeContainer(&c, model.RestartPolicyNever), true)
		if err != nil {
			return err
		}
		err = w.runtime.RemoveContainer(ctx, c.Name)
		if err != nil {
			return err
		}
	}
	return nil
}

const (
	startProbeCheckInterval = 5 * time.Second
	defaultCheckTimeout     = 3 * time.Second
	defaultProbeTimeout     = 2 * time.Minute
)

func (w *executor) waitContainersReady(ctx context.Context, containers ...model.ContainerDefinition) error {
	group := sync.NewGroup(0)

	for _, container := range containers {
		w.Infof("wait for container %s ready", container.Name)
		containerName := container.Name
		probe := w.loadContainerProbe(container.StartupProbe)
		group.Go(func() error {
			return wait.PollImmediate(startProbeCheckInterval, time.Duration(probe.ProbeTimeout)*time.Second, func() (bool, error) {
				err := w.doCheck(ctx, containerName, probe)
				if err != nil {
					w.Infof("check container %s not ready: %s", containerName, err)
					if ctxErr := ctx.Err(); ctxErr != nil {
						return false, ctxErr
					}
					return false, nil
				}
				w.Infof("check container %s has been ready", containerName)
				return true, nil
			})
		})
	}

	return group.WaitResult()
}

func (w *executor) loadContainerProbe(probe *model.ContainerProbe) *model.ContainerProbe {
	if probe == nil {
		return &model.ContainerProbe{
			CheckTimeout: int(defaultCheckTimeout / time.Second),
			ProbeTimeout: int(defaultProbeTimeout / time.Second),
		}
	}
	if probe.CheckTimeout == 0 {
		probe.CheckTimeout = int(defaultCheckTimeout / time.Second)
	}
	if probe.ProbeTimeout == 0 {
		probe.ProbeTimeout = int(defaultProbeTimeout / time.Second)
	}
	return probe
}

func (w *executor) startContainers(ctx context.Context, containers ...model.ContainerDefinition) error {
	for item := range containers {
		// fix: Implicit memory aliasing in for loop
		c := containers[item]
		w.Infof("start container %s", c.Name)
		err := w.runtime.CreateContainer(ctx, toRuntimeContainer(&c, model.RestartPolicyAlways), false)
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *executor) removeAllInNamespace(ctx context.Context) error {
	err := w.removeContainersInNamespace(ctx)
	if err != nil {
		return err
	}
	err = w.removeUnusedImages(ctx)
	if err != nil {
		return err
	}
	err = w.removeLeasesInNamespace(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (w *executor) removeUnusedImages(ctx context.Context, exceptImagesInContainer ...model.ContainerDefinition) error {
	images, err := w.runtime.ListImages(ctx)
	if err != nil {
		return err
	}

	imageSet := sets.NewString()
	for _, i := range images {
		imageSet.Insert(i.Name)
	}

	for _, c := range exceptImagesInContainer {
		imageSet.Delete(c.Image)
	}

	for _, image := range imageSet.List() {
		w.Infof("remove image %s from containerd", image)
		err := w.runtime.RemoveImage(ctx, image)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *executor) removeLeasesInNamespace(ctx context.Context) error {
	p, ok := w.runtime.(client.ContainerdClientProvider)
	if !ok {
		return errors.New("unsupported remove leases")
	}
	c := p.ContainerdClient()
	ctx = namespaces.WithNamespace(ctx, w.runtime.Namespace())

	leasess, err := c.LeasesService().List(ctx)
	if err != nil {
		return fmt.Errorf("list leases: %w", err)
	}

	for _, lease := range leasess {
		err = c.LeasesService().Delete(ctx, lease, leases.SynchronousDelete)
		if err != nil {
			return fmt.Errorf("remove lease %s: %w", lease.ID, err)
		}
	}
	return nil
}

func (w *executor) updateOperationMetadata(ctx context.Context) error {
	return w.doUpdateOperationMetadata(
		ctx,
		fmt.Sprintf("%x", sha1.Sum(lo.Must(yaml.Marshal(w.instance)))),
		strconv.FormatInt(time.Now().Unix(), 10),
	)
}

func (w *executor) removeOperationMetadata(ctx context.Context) error {
	return w.doUpdateOperationMetadata(ctx, "", "")
}

func (w *executor) doUpdateOperationMetadata(ctx context.Context, pluginHash, timestamp string) error {
	p, ok := w.runtime.(client.ContainerdClientProvider)
	if !ok {
		return nil
	}
	c := nsapi.NewNamespacesClient(p.ContainerdClient().Conn())

	req := nsapi.UpdateNamespaceRequest{
		Namespace: nsapi.Namespace{
			Labels: map[string]string{
				NamespaceLabelPluginHash:            pluginHash,
				NamespaceLabelPluginUpdateTimestamp: timestamp,
			},
			Name: w.runtime.Namespace(),
		},
		UpdateMask: &types.FieldMask{Paths: []string{
			strings.Join([]string{"labels", NamespaceLabelPluginHash}, "."),
			strings.Join([]string{"labels", NamespaceLabelPluginUpdateTimestamp}, "."),
		}},
	}

	ctx = namespaces.WithNamespace(ctx, w.runtime.Namespace())
	return errdefs.FromGRPC(lo.T2(c.Update(ctx, &req)).B)
}

func (w *executor) setupLogging(ctx context.Context) error {
	if w.logging == nil {
		return nil
	}
	return w.logging.SetupLogging(ctx)
}

func (w *executor) removeLogging(ctx context.Context) error {
	if w.logging == nil {
		return nil
	}
	return w.logging.RemoveLogging(ctx)
}

func (w *executor) setupMetrics(ctx context.Context) error {
	if w.metrics == nil {
		return nil
	}
	return w.metrics.SetupMetrics(ctx)
}

func (w *executor) removeMetrics(ctx context.Context) error {
	if w.metrics == nil {
		return nil
	}
	return w.metrics.RemoveMetrics(ctx)
}

// we reuse the checkClient to reuse the tcp connection
// #nosec G402
var checkClient = &http.Client{
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

// doCheck check container health, return null on healthy
func (w *executor) doCheck(ctx context.Context, containerName string, probe *model.ContainerProbe) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(probe.CheckTimeout)*time.Second)
	defer cancel()

	if probe.HTTPGet != "" {
		// do check with http get
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.HTTPGet, nil)
		if err != nil {
			return fmt.Errorf("make request: %s", err)
		}

		resp, err := checkClient.Do(request)
		if err != nil {
			return fmt.Errorf("do request: %s", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 500 && resp.StatusCode >= 100 {
			return nil
		}
		out, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpect http response code: %d, playload: %s", resp.StatusCode, string(out))
	}

	if len(probe.ExecCommand) != 0 {
		// do check with exec command in container
		result, err := w.runtime.ExecCommand(ctx, containerName, probe.ExecCommand)
		err = client.HandleTaskResult(result, err)
		if err != nil {
			return fmt.Errorf("exec command %v: %s", probe.ExecCommand, err)
		}
		return nil
	}

	// check if container is running
	status, err := w.runtime.GetContainerStatus(ctx, containerName)
	if err != nil {
		return fmt.Errorf("get container %s status: %s", containerName, err)
	}

	if status.Status.Status != containerd.Running {
		return fmt.Errorf("container status is %s not running", status.Status.Status)
	}

	return nil
}

type errorWrapExecutor struct {
	executor    Executor
	errorPrefix string
}

func (e *errorWrapExecutor) Close() error {
	return errors.Wrap(e.executor.Close(), e.errorPrefix)
}

func (e *errorWrapExecutor) Precheck(ctx context.Context) error {
	return errors.Wrap(e.executor.Precheck(ctx), e.errorPrefix)
}

func (e *errorWrapExecutor) Apply(ctx context.Context) error {
	return errors.Wrap(e.executor.Apply(ctx), e.errorPrefix)
}

func (e *errorWrapExecutor) Remove(ctx context.Context) error {
	return errors.Wrap(e.executor.Remove(ctx), e.errorPrefix)
}

func (e *errorWrapExecutor) HealthProbe(ctx context.Context) *model.PluginInstanceHealthResult {
	return e.executor.HealthProbe(ctx)
}

// toRuntimeContainer convert template defined containers to api container
func toRuntimeContainer(apiContainer *model.ContainerDefinition, restartPolicy model.RestartPolicy) *model.Container {
	var args []string
	if apiContainer.Process.Command == "" {
		args = apiContainer.Process.Args
	} else {
		args = append([]string{apiContainer.Process.Command}, apiContainer.Process.Args...)
	}
	c := &model.Container{
		Name:  apiContainer.Name,
		Image: apiContainer.Image,
		Process: model.Process{
			Args:          args,
			Env:           apiContainer.Process.Env,
			WorkingDir:    apiContainer.Process.WorkingDir,
			LogPath:       apiContainer.Process.LogPath,
			RestartPolicy: restartPolicy,
		},
	}

	if apiContainer.Logging != nil && apiContainer.Logging.Path != "" {
		c.Process.LogPath = apiContainer.Logging.Path
	}

	if apiContainer.Resources != nil {
		c.CgroupParent = apiContainer.Resources.CgroupParent
		c.MemoryLimit = apiContainer.Resources.Memory
		c.CPUPeriod = apiContainer.Resources.CPUPeriod
		c.CPUQuota = apiContainer.Resources.CPUQuota
		c.Privilege = apiContainer.Resources.Privileged
		c.Capabilities = apiContainer.Resources.Capabilities
		c.Devices = apiContainer.Resources.Devices
		for _, rlimit := range apiContainer.Resources.Rlimits {
			c.Rlimits = append(c.Rlimits, specs.POSIXRlimit{Type: rlimit.Type, Hard: rlimit.Hard, Soft: rlimit.Soft})
		}
	}

	if apiContainer.Runtime != nil {
		c.Runtime = model.Runtime{
			NoPivotRoot:   apiContainer.Runtime.NoPivotRoot,
			BinaryName:    apiContainer.Runtime.BinaryName,
			SystemdCgroup: apiContainer.Runtime.SystemdCgroup,
		}
	}

	for _, specPatch := range apiContainer.SpecPatches {
		c.SpecPatches = append(c.SpecPatches, []byte(specPatch))
	}

	for _, mount := range apiContainer.Mounts {
		c.Mounts = append(c.Mounts, specs.Mount{
			Destination: mount.Destination,
			Type:        mount.Type,
			Source:      mount.Source,
			Options:     mount.Options,
		})
	}

	return c.Complete()
}

func namespaceExists(ctx context.Context, runtime client.Runtime) (bool, error) {
	cp, ok := runtime.(client.ContainerdClientProvider)
	if !ok {
		return false, fmt.Errorf("require containerd client")
	}

	nss, err := cp.ContainerdClient().NamespaceService().List(ctx)
	if err != nil {
		return false, err
	}
	return sets.NewString(nss...).Has(runtime.Namespace()), nil
}

func namespaceLabels(ctx context.Context, runtime client.Runtime) (map[string]string, error) {
	p, ok := runtime.(client.ContainerdClientProvider)
	if !ok {
		return nil, nil
	}
	ctx = namespaces.WithNamespace(ctx, runtime.Namespace())
	return p.ContainerdClient().NamespaceService().Labels(ctx, runtime.Namespace())
}
