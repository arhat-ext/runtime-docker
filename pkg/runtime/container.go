/*
Copyright 2020 The arhat.dev Authors.

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

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"arhat.dev/aranya-proto/aranyagopb"
	"arhat.dev/aranya-proto/aranyagopb/runtimepb"
	extypes "arhat.dev/libext/types"
	"arhat.dev/pkg/log"
	"arhat.dev/pkg/wellknownerrors"
	"ext.arhat.dev/runtimeutil"
	"ext.arhat.dev/runtimeutil/storage"
	dockertype "github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
	dockerfilter "github.com/docker/docker/api/types/filters"
	dockermount "github.com/docker/docker/api/types/mount"
	dockerclient "github.com/docker/docker/client"
	dockercopy "github.com/docker/docker/pkg/stdcopy"
	dockernat "github.com/docker/go-connections/nat"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

func (r *dockerRuntime) listContainersByLabels(
	ctx context.Context, labels map[string]string,
) ([]*dockertype.Container, error) {
	findCtx, cancelFind := r.PodActionContext(ctx)
	defer cancelFind()

	filters := dockerfilter.NewArgs()
	for k, v := range labels {
		filters.Add("label", fmt.Sprintf("%s=%s", k, v))
	}

	containers, err := r.runtimeClient.ContainerList(findCtx, dockertype.ContainerListOptions{
		Quiet:   true,
		Filters: filters,
	})
	if err != nil {
		return nil, err
	}

	result := make([]*dockertype.Container, len(containers))
	for i := range containers {
		result[i] = &containers[i]
	}

	return result, nil
}

func (r *dockerRuntime) listPauseContainers(ctx context.Context) ([]*dockertype.Container, error) {
	return r.listContainersByLabels(
		ctx,
		map[string]string{
			runtimeutil.ContainerLabelPodContainerRole: runtimeutil.ContainerRoleInfra,
		},
	)
}

func (r *dockerRuntime) findContainerByLabels(
	ctx context.Context, labels map[string]string,
) (*dockertype.Container, error) {
	containers, err := r.listContainersByLabels(ctx, labels)
	if err != nil {
		return nil, err
	}

	if len(containers) == 0 {
		return nil, wellknownerrors.ErrNotFound
	}

	return containers[0], nil
}

func (r *dockerRuntime) findContainer(ctx context.Context, podUID, container string) (*dockertype.Container, error) {
	return r.findContainerByLabels(ctx,
		map[string]string{
			runtimeutil.ContainerLabelPodUID:       podUID,
			runtimeutil.ContainerLabelPodContainer: container,
		},
	)
}

func (r *dockerRuntime) findAbbotContainer(ctx context.Context) (*dockertype.Container, error) {
	return r.findContainerByLabels(ctx, runtimeutil.AbbotMatchLabels())
}

func (r *dockerRuntime) execInContainer(
	ctx context.Context,
	ctrID string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	command []string,
	tty bool,
	env map[string]string,
	errCh chan<- *aranyagopb.ErrorMsg,
) (extypes.ResizeHandleFunc, error) {
	execCtx, cancelExec := r.ActionContext(ctx)
	defer cancelExec()

	resp, err := r.runtimeClient.ContainerExecCreate(
		execCtx,
		ctrID,
		dockertype.ExecConfig{
			Tty:          tty,
			AttachStdin:  stdin != nil,
			AttachStdout: stdout != nil,
			AttachStderr: stderr != nil,
			Cmd:          command,
			Env:          formatEnv(env),
		},
	)
	if err != nil {
		return nil, err
	}

	attachResp, err := r.runtimeClient.ContainerExecAttach(
		execCtx, resp.ID, dockertype.ExecStartCheck{Tty: tty},
	)
	if err != nil {
		return nil, err
	}

	var stdOut, stdErr io.Writer
	stdOut, stdErr = stdout, stderr
	if stdout == nil {
		stdOut = ioutil.Discard
	}
	if stderr == nil {
		stdErr = ioutil.Discard
	}

	go func() {
		defer func() {
			defer func() {
				_ = recover()
			}()

			_ = attachResp.Conn.Close()

			close(errCh)
		}()

		// Here, we only wait for the output
		// since input (stdin) and resize (tty) are optional
		// and kubectl doesn't have a detach option, so the stdout will always be there

		var plainErr error
		if tty {
			_, plainErr = io.Copy(stdOut, attachResp.Reader)
		} else {
			_, plainErr = dockercopy.StdCopy(stdOut, stdErr, attachResp.Reader)
		}

		if plainErr != nil {
			select {
			case errCh <- &aranyagopb.ErrorMsg{
				Kind:        aranyagopb.ERR_COMMON,
				Description: plainErr.Error(),
			}:
			case <-ctx.Done():
			}
		}
	}()

	if stdin != nil {
		go func() {
			defer func() {
				_ = recover()
			}()

			_, plainErr := io.Copy(attachResp.Conn, stdin)
			if plainErr != nil {
				select {
				case errCh <- &aranyagopb.ErrorMsg{
					Kind:        aranyagopb.ERR_COMMON,
					Description: plainErr.Error(),
				}:
				case <-ctx.Done():
				}
			}
		}()
	}

	return func(cols, rows uint32) {
		_ = r.runtimeClient.ContainerExecResize(execCtx, resp.ID, dockertype.ResizeOptions{
			Height: uint(rows),
			Width:  uint(cols),
		})
	}, nil
}

// nolint:goconst
func (r *dockerRuntime) createPauseContainer(
	ctx context.Context,
	options *runtimepb.PodEnsureCmd,
) (ctrInfo *dockertype.ContainerJSON, abbotRespBytes []byte, err error) {
	_, err = r.findContainer(ctx, options.PodUid, runtimeutil.ContainerNamePause)
	if err == nil {
		return nil, nil, wellknownerrors.ErrAlreadyExists
	} else if !errors.Is(err, wellknownerrors.ErrNotFound) {
		return nil, nil, err
	}

	// refuse to create pod using cluster network if no abbot found
	if !options.HostNetwork {
		_, err = r.findAbbotContainer(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("abbot container required but not found: %w", err)
		}
	}

	var (
		hosts        []string
		exposedPorts = make(dockernat.PortSet)
		portBindings = make(dockernat.PortMap)
		hostname     string
		logger       = r.logger.WithFields(log.String("action", "createPauseContainer"))
	)

	switch {
	case options.HostNetwork:
		hostname = ""
	case options.Hostname != "":
		hostname = options.Hostname
	default:
		hostname = options.Name
	}

	for k, v := range options.Network.Hosts {
		hosts = append(hosts, fmt.Sprintf("%s:%s", k, v))
	}

	pauseCtrName := runtimeutil.GetContainerName(options.Namespace, options.Name, runtimeutil.ContainerNamePause)
	pauseCtr, err := r.runtimeClient.ContainerCreate(ctx,
		&dockercontainer.Config{
			Image:           r.pauseImage,
			Entrypoint:      r.pauseCommand,
			ExposedPorts:    exposedPorts,
			Hostname:        hostname,
			NetworkDisabled: !options.HostNetwork,
			Labels:          runtimeutil.ContainerLabels(options, runtimeutil.ContainerNamePause),
		},
		&dockercontainer.HostConfig{
			Resources: dockercontainer.Resources{
				MemorySwap: 0,
				CPUShares:  2,
			},

			ExtraHosts: hosts,
			Mounts:     []dockermount.Mount{},

			PortBindings:  portBindings,
			RestartPolicy: r.translateRestartPolicy(runtimepb.RESTART_ALWAYS),

			// kernel namespaces
			NetworkMode: func() dockercontainer.NetworkMode {
				if options.HostNetwork {
					return "host"
				}
				return ""
			}(),
			IpcMode: func() dockercontainer.IpcMode {
				if options.HostIpc {
					return "host"
				}
				return "shareable"
			}(),
			PidMode: func() dockercontainer.PidMode {
				if options.HostPid {
					return "host"
				}
				return "container"
			}(),
		},
		nil,
		&ocispecs.Platform{
			Architecture: "",
			OS:           "",
			OSVersion:    "",
			OSFeatures:   nil,
			Variant:      "",
		},
		pauseCtrName,
	)

	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			err2 := r.deleteContainer(ctx, pauseCtr.ID, true)
			if err2 != nil {
				logger.I("failed to delete pause container when error happened", log.Error(err2))
			}
		}
	}()

	err = r.runtimeClient.ContainerStart(ctx, pauseCtr.ID, dockertype.ContainerStartOptions{})
	if err != nil {
		return nil, nil, err
	}

	pauseCtrSpec, err := r.runtimeClient.ContainerInspect(ctx, pauseCtr.ID)
	if err != nil {
		return nil, nil, err
	}

	// handle cni network setup
	if !options.HostNetwork {
		abbotRespBytes, err = r.networkClient.Do(
			ctx,
			options.Network.AbbotRequestBytes,
			int64(pauseCtrSpec.State.Pid),
			pauseCtr.ID,
		)
		if err != nil {
			return nil, nil, err
		}
	}

	return &pauseCtrSpec, abbotRespBytes, nil
}

func (r *dockerRuntime) createContainer(
	ctx context.Context,
	options *runtimepb.PodEnsureCmd,
	spec *runtimepb.ContainerSpec,
	ns map[string]string,
) (ctrID string, err error) {
	_, err = r.findContainer(ctx, options.PodUid, spec.Name)
	if err == nil {
		return "", wellknownerrors.ErrAlreadyExists
	} else if !errors.Is(err, wellknownerrors.ErrNotFound) {
		return "", err
	}

	var (
		userAndGroup      string
		containerVolumes  = make(map[string]struct{})
		containerBinds    []string
		mounts            []dockermount.Mount
		envs              = formatEnv(spec.Envs)
		hostPaths         = options.GetVolumes().GetHostPaths()
		volumeData        = options.GetVolumes().GetVolumeData()
		containerFullName = runtimeutil.GetContainerName(options.Namespace, options.Name, spec.Name)
		healthCheck       *dockercontainer.HealthConfig
		maskedPaths       []string
		readonlyPaths     []string
	)
	// generalize to avoid panic
	if hostPaths == nil {
		hostPaths = make(map[string]string)
	}

	if volumeData == nil {
		volumeData = make(map[string]*runtimepb.NamedData)
	}

	switch spec.GetSecurity().GetProcMountKind() {
	case runtimepb.PROC_MOUNT_DEFAULT:
		maskedPaths = nil
		readonlyPaths = nil
	case runtimepb.PROC_MOUNT_UNMASKED:
		maskedPaths = make([]string, 0)
		readonlyPaths = make([]string, 0)
	}

	for volName, volMountSpec := range spec.Mounts {
		var source string

		containerVolumes[volMountSpec.MountPath] = struct{}{}
		// check if it is host volume or emptyDir
		hostPath, isHostVol := hostPaths[volName]
		if isHostVol {
			source, err = runtimeutil.ResolveHostPathMountSource(
				hostPath, options.PodUid, volName, volMountSpec.Remote,
				r.PodRemoteVolumeDir, r.PodTmpfsVolumeDir,
			)
			if err != nil {
				return "", err
			}

			if volMountSpec.Remote {
				// for remote volume, hostPath is the aranya pod host path
				err = r.storageClient.Mount(
					ctx,
					hostPath,
					source,
					r.handleStorageFailure(options.PodUid),
				)
				if err != nil {
					return "", err
				}
			}
		}

		// check if it is vol data (from configMap, Secret)
		if volData, isVolData := volumeData[volName]; isVolData {
			if dataMap := volData.GetDataMap(); dataMap != nil {
				dir := r.PodBindVolumeDir(options.PodUid, volName)
				if err = os.MkdirAll(dir, 0750); err != nil {
					return "", err
				}

				source, err = volMountSpec.Ensure(dir, dataMap)
				if err != nil {
					return "", err
				}
			}
		}

		mounts = append(mounts, dockermount.Mount{
			Type:        dockermount.TypeBind,
			Source:      source,
			Target:      filepath.Join(volMountSpec.MountPath, volMountSpec.SubPath),
			ReadOnly:    volMountSpec.ReadOnly,
			Consistency: dockermount.ConsistencyFull,
		})
	}

	if netOpts := options.Network; len(netOpts.Nameservers) != 0 {
		resolvConfFile := r.PodResolvConfFile(options.PodUid)
		if err = os.MkdirAll(filepath.Dir(resolvConfFile), 0750); err != nil {
			return "", err
		}

		var data []byte
		data, err = r.networkClient.CreateResolvConf(
			netOpts.Nameservers, netOpts.DnsSearches, netOpts.DnsOptions,
		)
		if err != nil {
			return "", err
		}

		if err = ioutil.WriteFile(resolvConfFile, data, 0440); err != nil {
			return "", err
		}

		mounts = append(mounts, dockermount.Mount{
			Type:        dockermount.TypeBind,
			Source:      resolvConfFile,
			Target:      "/etc/resolv.conf",
			Consistency: dockermount.ConsistencyFull,
		})
	}

	if spec.Security != nil {
		builder := &strings.Builder{}
		if uid := spec.Security.GetUser(); uid != -1 {
			builder.WriteString(strconv.FormatInt(uid, 10))
		}

		if gid := spec.Security.GetGroup(); gid != -1 {
			builder.WriteString(":")
			builder.WriteString(strconv.FormatInt(gid, 10))
		}
		userAndGroup = builder.String()
	}

	if probe := spec.LivenessCheck; probe != nil && probe.Method != nil {
		switch action := spec.LivenessCheck.Method.Action.(type) {
		case *runtimepb.ContainerAction_Exec_:
			healthCheck = &dockercontainer.HealthConfig{
				Test:        append([]string{"CMD"}, action.Exec.Command...),
				Interval:    time.Duration(probe.ProbeInterval),
				Timeout:     time.Duration(probe.ProbeTimeout),
				StartPeriod: time.Duration(probe.InitialDelay),
				Retries:     int(probe.FailureThreshold),
				// TODO: implement success threshold
			}
		case *runtimepb.ContainerAction_Socket_:
			// TODO: implement
		case *runtimepb.ContainerAction_Http:
			// TODO: implement
		}
	}

	containerConfig := &dockercontainer.Config{
		User: userAndGroup,

		Tty:       spec.Tty,
		OpenStdin: spec.Stdin,
		StdinOnce: spec.StdinOnce,

		Env: envs,

		Entrypoint: spec.Command,
		Cmd:        spec.Args,

		Healthcheck: healthCheck,

		Image:      spec.Image,
		Volumes:    containerVolumes,
		WorkingDir: spec.WorkingDir,

		Labels:     runtimeutil.ContainerLabels(options, spec.Name),
		StopSignal: "SIGTERM",
	}
	hostConfig := &dockercontainer.HostConfig{
		Resources: dockercontainer.Resources{MemorySwap: 0, CPUShares: 2},
		// volume mounts
		Binds:  containerBinds,
		Mounts: mounts,

		RestartPolicy: r.translateRestartPolicy(options.RestartPolicy),
		// share namespaces
		NetworkMode: dockercontainer.NetworkMode(ns["net"]),
		IpcMode:     dockercontainer.IpcMode(ns["ipc"]),
		UTSMode:     dockercontainer.UTSMode(ns["uts"]),
		UsernsMode:  dockercontainer.UsernsMode(ns["user"]),
		PidMode:     dockercontainer.PidMode(ns["pid"]),

		// security options
		Privileged:     spec.Security.GetPrivileged(),
		CapAdd:         spec.Security.GetCapsAdd(),
		CapDrop:        spec.Security.GetCapsDrop(),
		ReadonlyRootfs: spec.Security.GetReadOnlyRootfs(),
		Sysctls:        options.GetSecurity().GetSysctls(),

		MaskedPaths:   maskedPaths,
		ReadonlyPaths: readonlyPaths,
	}

	ctr, err := r.runtimeClient.ContainerCreate(ctx, containerConfig, hostConfig, nil,
		&ocispecs.Platform{
			Architecture: "",
			OS:           "",
			OSVersion:    "",
			OSFeatures:   nil,
			Variant:      "",
		},
		containerFullName,
	)
	if err != nil {
		return "", err
	}

	return ctr.ID, nil
}

// deleteContainer return nil if container not found or deleted successfully
func (r *dockerRuntime) deleteContainer(ctx context.Context, containerID string, isPauseCtr bool) error {
	if isPauseCtr {
		// network manager is available
		pauseCtr, err := r.runtimeClient.ContainerInspect(ctx, containerID)
		if err != nil {
			if dockerclient.IsErrNotFound(err) {
				// container already deleted, no more effort
				return nil
			}
		}

		if runtimeutil.IsAbbotPod(pauseCtr.Config.Labels) {
			var containers []*dockertype.Container
			containers, err = r.listPauseContainers(ctx)
			if err != nil {
				return err
			}

			for _, ctr := range containers {
				if !runtimeutil.IsHostNetwork(ctr.Labels) {
					return wellknownerrors.ErrInvalidOperation
				}
			}
		}

		if !runtimeutil.IsHostNetwork(pauseCtr.Config.Labels) {
			err = r.networkClient.Delete(ctx, int64(pauseCtr.State.Pid), pauseCtr.ID)
			if err != nil {
				return err
			}
		}
	}

	// stop with best effort
	timeout := time.Duration(0)
	_ = r.runtimeClient.ContainerStop(context.Background(), containerID, &timeout)

	err := r.runtimeClient.ContainerRemove(context.Background(), containerID, dockertype.ContainerRemoveOptions{
		RemoveVolumes: true,
		Force:         true,
	})

	if err != nil && !dockerclient.IsErrNotFound(err) {
		return err
	}
	return nil
}

func (r *dockerRuntime) handleStorageFailure(podUID string) storage.ExitHandleFunc {
	logger := r.logger.WithFields(log.String("module", "storage"), log.String("podUID", podUID))
	return func(remotePath, mountPoint string, err error) {
		if err != nil {
			logger.I("storage mounter exited", log.Error(err))
		}

		_, e := r.findContainer(context.TODO(), podUID, runtimeutil.ContainerNamePause)
		if errors.Is(e, wellknownerrors.ErrNotFound) {
			logger.D("pod not found, no more remount action")
			return
		}

		err = r.storageClient.Mount(context.TODO(), remotePath, mountPoint, r.handleStorageFailure(podUID))
		if err != nil {
			logger.I("failed to mount remote volume", log.Error(err))
		}
	}
}
