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
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"

	"arhat.dev/libext/extruntime"
	"arhat.dev/pkg/log"
	"ext.arhat.dev/runtimeutil/containerutil"
	"ext.arhat.dev/runtimeutil/networkutil"
	"ext.arhat.dev/runtimeutil/storageutil"
	dockertype "github.com/docker/docker/api/types"
	dockerclient "github.com/docker/docker/client"

	"ext.arhat.dev/runtime-docker/pkg/conf"
)

func NewDockerRuntime(
	ctx context.Context,
	logger log.Interface,
	storage *storageutil.Client,
	config *conf.RuntimeConfig,
) (extruntime.RuntimeEngine, error) {
	dialCtxFunc := func(timeout time.Duration) func(
		ctx context.Context, network, addr string,
	) (conn net.Conn, e error) {
		return func(ctx context.Context, network, addr string) (conn net.Conn, e error) {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			var dialer net.Dialer
			if filepath.IsAbs(addr) {
				network = "unix"
				idx := strings.LastIndexByte(addr, ':')
				if idx != -1 {
					addr = addr[:idx]
				}
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}

	runtimeClient, err := dockerclient.NewClientWithOpts(
		dockerclient.WithAPIVersionNegotiation(),
		dockerclient.WithHost(config.Endpoint),
		dockerclient.WithDialContext(dialCtxFunc(config.DialTimeout)),
		dockerclient.FromEnv,
	)
	if err != nil {
		return nil, err
	}

	infoCtx, cancelInfo := context.WithTimeout(ctx, config.PodActionTimeout)
	defer cancelInfo()

	versions, err := runtimeClient.ServerVersion(infoCtx)
	if err != nil {
		return nil, err
	}

	version := ""
	for _, ver := range versions.Components {
		if strings.ToLower(ver.Name) == "engine" {
			version = ver.Version
		}
	}

	rt := &dockerRuntime{
		BaseRuntime: containerutil.NewBaseRuntime(
			ctx, config.DataDir,
			config.ImageActionTimeout,
			config.PodActionTimeout,
			"docker",
			version,
			versions.Os,
			"",
			versions.Arch,
			versions.KernelVersion,
		),
		logger: logger,

		pauseImage:   config.PauseImage,
		pauseCommand: config.PauseCommand,

		imageClient:   runtimeClient,
		runtimeClient: runtimeClient,

		networkClient: nil,
		storageClient: storage,
	}

	rt.networkClient = networkutil.NewClient(
		func(ctx context.Context, env map[string]string, stdin io.Reader, stdout, stderr io.Writer) error {
			abbotCtrInfo, err := rt.findAbbotContainer(ctx)
			if err != nil {
				return err
			}

			cmd := append(strings.Split(abbotCtrInfo.Command, " "), config.AbbotRequestSubCmd)

			_, errCh, err := rt.execInContainer(ctx, abbotCtrInfo.ID, stdin, stdout, stderr, cmd, false, env)
			if err != nil {
				return err
			}

			// only one or no error will return
			return <-errCh
		},
	)

	return rt, nil
}

type dockerRuntime struct {
	appCtx context.Context
	logger log.Interface

	pauseImage   string
	pauseCommand []string

	*containerutil.BaseRuntime

	runtimeClient dockerclient.ContainerAPIClient
	imageClient   dockerclient.ImageAPIClient

	networkClient *networkutil.Client
	storageClient *storageutil.Client
}

func (r *dockerRuntime) InitRuntime() error {
	logger := r.logger.WithFields(log.String("action", "init"))
	ctx, cancelInit := r.ActionContext(r.appCtx)
	defer cancelInit()

	logger.D("looking up abbot container")
	abbotCtrInfo, err := r.findAbbotContainer(r.appCtx)
	if err == nil {
		podUID := abbotCtrInfo.Labels[containerutil.ContainerLabelPodUID]
		logger.D("looking up pause container for abbot container")
		pauseCtrInfo, err := r.findContainer(r.appCtx, podUID, containerutil.ContainerNamePause)
		if err == nil {
			logger.D("starting pause container for abbot container")
			plainErr := r.runtimeClient.ContainerStart(ctx, pauseCtrInfo.ID, dockertype.ContainerStartOptions{})
			if plainErr != nil {
				logger.I("failed to start pause container for abbot container", log.Error(plainErr))
			}
		}

		logger.D("starting abbot container")
		plainErr := r.runtimeClient.ContainerStart(ctx, abbotCtrInfo.ID, dockertype.ContainerStartOptions{})
		if plainErr != nil {
			return fmt.Errorf("failed to start abbot container: %v", plainErr)
		}
	}

	containers, plainErr := r.runtimeClient.ContainerList(ctx, dockertype.ContainerListOptions{
		Quiet: true,
		All:   true,
	})
	if plainErr != nil {
		return plainErr
	}

	var (
		pauseContainers []dockertype.Container
		workContainers  []dockertype.Container
	)
	for i, ctr := range containers {
		if _, ok := ctr.Labels[containerutil.ContainerLabelPodUID]; ok {
			switch ctr.Labels[containerutil.ContainerLabelPodContainerRole] {
			case containerutil.ContainerRoleInfra:
				pauseContainers = append(pauseContainers, containers[i])
			case containerutil.ContainerRoleWork:
				workContainers = append(workContainers, containers[i])
			}
		}
	}

	for _, ctr := range pauseContainers {
		logger.D("starting pause container", log.Strings("names", ctr.Names))
		err := r.runtimeClient.ContainerStart(ctx, ctr.ID, dockertype.ContainerStartOptions{})
		if err != nil {
			logger.I("failed to start pause container", log.Strings("names", ctr.Names), log.Error(err))
			return err
		}

		if containerutil.IsHostNetwork(ctr.Labels) {
			continue
		}

		pauseCtr, err := r.runtimeClient.ContainerInspect(ctx, ctr.ID)
		if err != nil {
			logger.I("failed to inspect pause container", log.Strings("names", ctr.Names), log.Error(err))
			return err
		}

		err = r.networkClient.Restore(ctx, int64(pauseCtr.State.Pid), pauseCtr.ID)
		if err != nil {
			logger.I("failed to restore container network")
			return err
		}
	}

	for _, ctr := range workContainers {
		logger.D("starting work container", log.Strings("names", ctr.Names))
		err := r.runtimeClient.ContainerStart(ctx, ctr.ID, dockertype.ContainerStartOptions{})
		if err != nil {
			logger.I("failed to start work container", log.Strings("names", ctr.Names), log.Error(err))
		}
	}

	return nil
}
