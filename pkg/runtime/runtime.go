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

	"arhat.dev/aranya-proto/aranyagopb"
	"arhat.dev/libext/extruntime"
	"arhat.dev/pkg/log"
	"ext.arhat.dev/runtimeutil"
	"ext.arhat.dev/runtimeutil/storage"
	dockertype "github.com/docker/docker/api/types"
	dockerclient "github.com/docker/docker/client"

	"ext.arhat.dev/runtime-docker/pkg/conf"
)

func NewDockerRuntime(
	ctx context.Context,
	logger log.Interface,
	storage *storage.Client,
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
		BaseRuntime: runtimeutil.NewBaseRuntime(
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

	rt.networkClient = runtimeutil.NewNetworkClient(
		func(ctx context.Context, env map[string]string, stdin io.Reader, stdout, stderr io.Writer) error {
			abbotCtrInfo, err := rt.findAbbotContainer(ctx)
			if err != nil {
				return err
			}

			cmd := append(strings.Split(abbotCtrInfo.Command, " "), config.AbbotRequestSubCmd)

			errCh := make(chan *aranyagopb.ErrorMsg, 2)
			_, err = rt.execInContainer(ctx, abbotCtrInfo.ID, stdin, stdout, stderr, cmd, false, env, errCh)
			if err != nil {
				return err
			}

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

	*runtimeutil.BaseRuntime

	runtimeClient dockerclient.ContainerAPIClient
	imageClient   dockerclient.ImageAPIClient

	networkClient *runtimeutil.NetworkClient
	storageClient *storage.Client
}

func (r *dockerRuntime) InitRuntime() error {
	logger := r.logger.WithFields(log.String("action", "init"))
	ctx, cancelInit := r.ActionContext(r.appCtx)
	defer cancelInit()

	logger.D("looking up abbot container")
	abbotCtrInfo, err := r.findAbbotContainer(r.appCtx)
	if err == nil {
		podUID := abbotCtrInfo.Labels[runtimeutil.ContainerLabelPodUID]
		logger.D("looking up pause container for abbot container")
		pauseCtrInfo, err := r.findContainer(r.appCtx, podUID, runtimeutil.ContainerNamePause)
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
		if _, ok := ctr.Labels[runtimeutil.ContainerLabelPodUID]; ok {
			switch ctr.Labels[runtimeutil.ContainerLabelPodContainerRole] {
			case runtimeutil.ContainerRoleInfra:
				pauseContainers = append(pauseContainers, containers[i])
			case runtimeutil.ContainerRoleWork:
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

		if runtimeutil.IsHostNetwork(ctr.Labels) {
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

//
//func (r *dockerRuntime) CreateInitContainers(ctx context.Context, options *runtimepb.PodEnsureCmd) (*runtimepb.PodStatusMsg, error) {
//	logger := r.logger.WithFields(
//		log.String("action", "createInitContainers"),
//		log.String("namespace", options.Namespace),
//		log.String("name", options.Name),
//		log.String("uid", options.PodUid))
//	logger.D("creating init containers")
//
//	ctx, cancelCreate := r.PodActionContext(ctx)
//	defer cancelCreate()
//
//	pauseCtr, abbotRespBytes, err := r.createPauseContainer(ctx, options)
//	if err != nil {
//		logger.I("failed to create pause container", log.Error(err))
//		return nil, err
//	}
//
//	defer func() {
//		if err != nil {
//			logger.D("deleting pause container due to error")
//			err2 := r.deleteContainer(ctx, pauseCtr.ID, true)
//			if err2 != nil {
//				logger.I("failed to delete pause container", log.Error(err2))
//			}
//
//			logger.D("cleaning up pod data")
//			err2 = runtimeutil.CleanupPodData(
//				r.PodDir(options.PodUid),
//				r.PodRemoteVolumeDir(options.PodUid, ""),
//				r.PodTmpfsVolumeDir(options.PodUid, ""),
//				r.storage,
//			)
//			if err2 != nil {
//				logger.E("failed to cleanup pod data", log.Error(err2))
//			}
//		}
//	}()
//
//	// create and wait for init containers
//	containers := make(map[string]*runtimepb.ContainerAction)
//	for _, spec := range options.Containers {
//		var ctrID string
//		ctrID, err = r.createContainer(ctx, options, spec, runtimeutil.SharedNamespaces(pauseCtr.ID, options))
//		if err != nil {
//			logger.I("failed to create container", log.String("container", spec.Name), log.Error(err))
//			return nil, err
//		}
//		containers[ctrID] = spec.HookPostStart
//
//		defer func(ctrID string) {
//			if err != nil {
//				logger.D("deleting init container due to error")
//				err := r.deleteContainer(ctx, ctrID, false)
//				if err != nil {
//					logger.I("failed to delete init container", log.Error(err))
//				}
//			}
//		}(ctrID)
//	}
//
//	wg := new(sync.WaitGroup)
//	respCh := make(chan dockertype.ContainerJSON, len(containers))
//	errCh := make(chan error, len(containers))
//	for ctrID, postStartHook := range containers {
//		waitRespCh, waitErrCh := r.runtimeClient.ContainerWait(ctx, ctrID, dockercontainer.WaitConditionNextExit)
//
//		wg.Add(1)
//		go func(ctrID string) {
//			defer func() {
//				wg.Done()
//
//				logger.D("deleting init container", log.String("id", ctrID))
//				err := r.deleteContainer(ctx, ctrID, false)
//				if err != nil {
//					logger.I("failed to delete init container", log.String("id", ctrID), log.Error(err))
//				}
//			}()
//
//			select {
//			case resp := <-waitRespCh:
//				if resp.StatusCode != 0 {
//					if resp.Error != nil {
//						errCh <- errors.New(resp.Error.Message)
//					} else {
//						errCh <- fmt.Errorf("container exited with code %d", resp.StatusCode)
//					}
//					return
//				}
//
//				// init container finished successfully, inspect container info
//				ctrInfo, plainErr := r.runtimeClient.ContainerInspect(ctx, ctrID)
//				if plainErr != nil {
//					errCh <- fmt.Errorf("failed to inspect init container [%s]: %v", ctrID, plainErr)
//					return
//				}
//
//				respCh <- ctrInfo
//			case err := <-waitErrCh:
//				errCh <- err
//				return
//			case <-ctx.Done():
//				errCh <- ctx.Err()
//				return
//			}
//		}(ctrID)
//
//		logger.D("starting init container")
//		err := r.runtimeClient.ContainerStart(ctx, ctrID, dockertype.ContainerStartOptions{})
//		if err != nil {
//			logger.I("failed to start init container", log.String("id", ctrID), log.Error(err))
//			return nil, err
//		}
//
//		if postStartHook != nil {
//			logger.D("executing post-start hook")
//			if err := r.doHookActions(logger, ctrID, postStartHook); err != nil {
//				logger.I("failed to execute post-start hook", log.StringError(err.Description))
//			}
//		}
//	}
//
//	// wait for init container operations
//	wg.Wait()
//
//	close(respCh)
//	close(errCh)
//
//	// check wait operation error
//	if err := runtimeutil.CollectErrors(errCh); err != nil {
//		return nil, err
//	}
//
//	// all init container finished successfully
//	var allCtrInfo []*dockertype.ContainerJSON
//	for ctrInfo := range respCh {
//		info := ctrInfo
//		allCtrInfo = append(allCtrInfo, &info)
//	}
//
//	return r.translatePodStatus(abbotRespBytes, pauseCtr, allCtrInfo), nil
//}
