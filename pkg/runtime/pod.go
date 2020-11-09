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

	"arhat.dev/aranya-proto/aranyagopb/runtimepb"
	"arhat.dev/pkg/log"
	"arhat.dev/pkg/wellknownerrors"
	dockertype "github.com/docker/docker/api/types"
	dockerfilter "github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"

	"ext.arhat.dev/runtimeutil"
)

func (r *dockerRuntime) EnsurePod(
	ctx context.Context,
	options *runtimepb.PodEnsureCmd,
) (_ *runtimepb.PodStatusMsg, err error) {
	logger := r.logger.WithFields(
		log.String("action", "create"),
		log.String("namespace", options.Namespace),
		log.String("name", options.Name),
		log.String("uid", options.PodUid),
	)
	logger.D("creating pod containers")

	ctx, cancelCreate := r.PodActionContext(ctx)
	defer func() {
		cancelCreate()

		if err != nil && !errors.Is(err, wellknownerrors.ErrAlreadyExists) {
			logger.D("cleaning up pod data")
			err2 := runtimeutil.CleanupPodData(
				r.PodDir(options.PodUid),
				r.PodRemoteVolumeDir(options.PodUid, ""),
				r.PodTmpfsVolumeDir(options.PodUid, ""),
				func(path string) error {
					return r.storageClient.Unmount(ctx, path)
				},
			)
			if err2 != nil {
				logger.E("failed to cleanup pod data", log.Error(err2))
			}
		}
	}()

	var (
		pauseCtrInfo   *dockertype.ContainerJSON
		abbotRespBytes []byte
	)

	pauseCtr, err := r.findContainer(ctx, options.PodUid, runtimeutil.ContainerNamePause)
	if err != nil {
		if errors.Is(err, wellknownerrors.ErrNotFound) {
			// need to create pause container
			pauseCtrInfo, abbotRespBytes, err = r.createPauseContainer(ctx, options)
			if err != nil {
				logger.I("failed to create pause container", log.Error(err))
				return nil, err
			}

			defer func() {
				if err != nil {
					logger.D("deleting pause container due to error")
					err2 := r.deleteContainer(ctx, pauseCtrInfo.ID, true)
					if err2 != nil {
						logger.I("failed to delete pause container", log.Error(err2))
					}
				}
			}()
		} else {
			return nil, err
		}
	} else {
		oldPauseCtrInfo, err := r.runtimeClient.ContainerInspect(ctx, pauseCtr.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to inspect existing pause container: %w", err)
		}

		pauseCtrInfo = &oldPauseCtrInfo
	}

	containers := make(map[string]*runtimepb.ContainerAction)
	for _, spec := range options.Containers {
		ctrLogger := logger.WithFields(log.String("container", spec.Name))
		ctrLogger.D("creating container")
		ctrID, err := r.createContainer(ctx, options, spec, runtimeutil.SharedNamespaces(pauseCtrInfo.ID, options))
		if err != nil {
			ctrLogger.I("failed to create container", log.Error(err))
			return nil, err
		}
		containers[ctrID] = spec.HookPostStart

		defer func(ctrID string) {
			if err != nil {
				ctrLogger.I("delete container due to error")
				if err := r.deleteContainer(ctx, ctrID, false); err != nil {
					ctrLogger.I("failed to delete container after start failure", log.Error(err))
				}
			}
		}(ctrID)
	}

	for ctrID, postStartHook := range containers {
		logger.D("starting container", log.String("id", ctrID))
		err := r.runtimeClient.ContainerStart(ctx, ctrID, dockertype.ContainerStartOptions{})
		if err != nil {
			logger.I("failed to start container", log.String("id", ctrID), log.Error(err))
			return nil, err
		}

		if postStartHook != nil {
			logger.D("executing post-start hook")
			if err := r.doHookActions(ctx, ctrID, postStartHook); err != nil {
				logger.I("failed to execute post-start hook", log.StringError(err.Description))
			}
		}
	}

	var allCtrInfo []*dockertype.ContainerJSON
	for ctrID := range containers {
		ctrInfo, err := r.runtimeClient.ContainerInspect(ctx, ctrID)
		if err != nil {
			logger.I("failed to inspect docker container", log.Error(err))
			return nil, err
		}
		allCtrInfo = append(allCtrInfo, &ctrInfo)
	}

	return r.translatePodStatus(abbotRespBytes, pauseCtrInfo, allCtrInfo), nil
}

func (r *dockerRuntime) DeletePod(
	ctx context.Context,
	options *runtimepb.PodDeleteCmd,
) (_ *runtimepb.PodStatusMsg, err error) {
	logger := r.logger.WithFields(log.String("action", "delete"), log.Any("options", options))
	logger.D("deleting pod containers")

	ctx, cancelDelete := r.PodActionContext(ctx)
	defer func() {
		cancelDelete()

		logger.D("cleaning up pod data")
		err2 := runtimeutil.CleanupPodData(
			r.PodDir(options.PodUid),
			r.PodRemoteVolumeDir(options.PodUid, ""),
			r.PodTmpfsVolumeDir(options.PodUid, ""),
			func(path string) error {
				return r.storageClient.Unmount(ctx, path)
			},
		)
		if err2 != nil {
			logger.E("failed to cleanup pod data", log.Error(err2))
		}
	}()

	containers, err := r.runtimeClient.ContainerList(ctx, dockertype.ContainerListOptions{
		Quiet: true,
		All:   true,
		Filters: dockerfilter.NewArgs(
			dockerfilter.Arg("label", fmt.Sprintf("%s=%s", runtimeutil.ContainerLabelPodUID, options.PodUid)),
		),
	})
	if err != nil && !dockerclient.IsErrNotFound(err) {
		logger.I("failed to list containers", log.Error(err))
		return nil, err
	}

	// delete work containers first
	pauseCtrIndex := -1
	for i, ctr := range containers {
		// find pause container
		if ctr.Labels[runtimeutil.ContainerLabelPodContainerRole] == runtimeutil.ContainerRoleInfra {
			pauseCtrIndex = i
			break
		}
	}
	lastIndex := len(containers) - 1
	// swap pause container to last
	if pauseCtrIndex != -1 {
		containers[lastIndex], containers[pauseCtrIndex] = containers[pauseCtrIndex], containers[lastIndex]
	}

	for i, ctr := range containers {
		logger.D("deleting container", log.Strings("names", ctr.Names))

		isPauseCtr := false
		if i == len(containers)-1 {
			// last one, is deleting pause container, we need to delete network first
			isPauseCtr = true
		}

		name := ctr.Labels[runtimeutil.ContainerLabelPodContainer]
		if options.HookPreStop != nil {
			if hook, ok := options.HookPreStop[name]; ok {
				logger.D("executing pre-stop hook", log.String("name", name))
				if err := r.doHookActions(ctx, ctr.ID, hook); err != nil {
					logger.I("failed to execute pre-stop hook", log.StringError(err.Description))
				}
			}
		}

		err = r.deleteContainer(ctx, ctr.ID, isPauseCtr)
		if err != nil {
			return nil, fmt.Errorf("failed to delete container: %w", err)
		}
	}

	logger.D("pod deleted")
	return runtimepb.NewPodStatusMsg(options.PodUid, nil, nil), nil
}

func (r *dockerRuntime) ListPods(
	ctx context.Context,
	options *runtimepb.PodListCmd,
) (*runtimepb.PodStatusListMsg, error) {
	logger := r.logger.WithFields(log.String("action", "list"), log.Any("options", options))
	logger.D("listing pods")

	ctx, cancelList := r.PodActionContext(ctx)
	defer cancelList()

	filter := dockerfilter.NewArgs()
	if !options.All {
		if len(options.Names) != 0 {
			// TODO: filter multiple names
			filter.Add("label", runtimeutil.ContainerLabelPodName+"="+options.Names[0])
		}
	}

	containers, err := r.runtimeClient.ContainerList(ctx, dockertype.ContainerListOptions{
		All:     options.All,
		Quiet:   true,
		Filters: filter,
	})
	if err != nil {
		logger.I("failed to list containers", log.Error(err))
		return nil, err
	}

	var (
		results []*runtimepb.PodStatusMsg
		// podUID -> pause container
		pauseContainers = make(map[string]dockertype.Container)
		// podUID -> containers
		podContainers = make(map[string][]dockertype.Container)
	)

	for _, ctr := range containers {
		podUID, hasUID := ctr.Labels[runtimeutil.ContainerLabelPodUID]
		if !hasUID {
			// not the container created by us
			continue
		}

		role, hasRole := ctr.Labels[runtimeutil.ContainerLabelPodContainerRole]
		if hasRole && role == runtimeutil.ContainerRoleInfra {
			pauseContainers[podUID] = ctr
			continue
		}

		podContainers[podUID] = append(podContainers[podUID], ctr)
	}

	// one pause container represents on Pod
	for podUID, pauseContainer := range pauseContainers {
		logger.D("inspecting pause container")
		pauseCtrSpec, err := r.runtimeClient.ContainerInspect(ctx, pauseContainer.ID)
		if err != nil {
			logger.I("failed to inspect pause container", log.Error(err))
			return nil, err
		}

		var containersInfo []*dockertype.ContainerJSON
		for _, ctr := range podContainers[podUID] {
			logger.D("inspecting work container")
			var ctrInfo dockertype.ContainerJSON
			ctrInfo, err = r.runtimeClient.ContainerInspect(ctx, ctr.ID)
			if err != nil {
				logger.I("failed to inspect work container", log.Error(err))
				return nil, err
			}
			containersInfo = append(containersInfo, &ctrInfo)
		}

		var abbotRespBytes []byte
		if !runtimeutil.IsHostNetwork(pauseCtrSpec.Config.Labels) {
			abbotRespBytes, err = r.networkClient.Query(ctx, int64(pauseCtrSpec.State.Pid), pauseCtrSpec.ID)
			if err != nil {
				return nil, err
			}
		}
		results = append(results, r.translatePodStatus(abbotRespBytes, &pauseCtrSpec, containersInfo))
	}

	return &runtimepb.PodStatusListMsg{Pods: results}, nil
}
