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
	"io/ioutil"
	"time"

	"arhat.dev/aranya-proto/aranyagopb/runtimepb"
	"ext.arhat.dev/runtimeutil"

	"arhat.dev/aranya-proto/aranyagopb"
	"arhat.dev/aranya-proto/aranyagopb/aranyagoconst"
	dockertype "github.com/docker/docker/api/types"
	dockercontainer "github.com/docker/docker/api/types/container"
)

var (
	restartAlways    = dockercontainer.RestartPolicy{Name: "always"}
	restartOnFailure = dockercontainer.RestartPolicy{Name: "on-failure"}
	restartNever     = dockercontainer.RestartPolicy{Name: "no"}
)

func (r *dockerRuntime) translateRestartPolicy(policy runtimepb.RestartPolicy) dockercontainer.RestartPolicy {
	switch policy {
	case runtimepb.RESTART_ALWAYS:
		return restartAlways
	case runtimepb.RESTART_ON_FAILURE:
		return restartOnFailure
	case runtimepb.RESTART_NEVER:
		return restartNever
	}

	return restartAlways
}

func (r *dockerRuntime) translatePodStatus(
	abbotRespBytes []byte,
	pauseContainer *dockertype.ContainerJSON,
	containers []*dockertype.ContainerJSON,
) *runtimepb.PodStatusMsg {
	podUID := pauseContainer.Config.Labels[runtimeutil.ContainerLabelPodUID]
	ctrStatus := make(map[string]*runtimepb.ContainerStatus)

	for _, ctr := range containers {
		ctrPodUID := ctr.Config.Labels[runtimeutil.ContainerLabelPodUID]
		name := ctr.Config.Labels[runtimeutil.ContainerLabelPodContainer]
		if name == "" || ctrPodUID != podUID {
			// invalid container, skip
			continue
		}

		status := r.translateContainerStatus(ctr)
		ctrStatus[name] = status
	}

	return runtimepb.NewPodStatusMsg(podUID, abbotRespBytes, ctrStatus)
}

func (r *dockerRuntime) translateContainerStatus(
	ctrInfo *dockertype.ContainerJSON,
) *runtimepb.ContainerStatus {
	ctrCreatedAt, _ := time.Parse(time.RFC3339Nano, ctrInfo.Created)
	ctrStartedAt, _ := time.Parse(time.RFC3339Nano, ctrInfo.State.StartedAt)
	ctrFinishedAt, _ := time.Parse(time.RFC3339Nano, ctrInfo.State.FinishedAt)

	return &runtimepb.ContainerStatus{
		ContainerId: r.Name() + "://" + ctrInfo.ID,
		ImageId:     ctrInfo.Image,
		CreatedAt:   ctrCreatedAt.Format(aranyagoconst.TimeLayout),
		StartedAt:   ctrStartedAt.Format(aranyagoconst.TimeLayout),
		FinishedAt:  ctrFinishedAt.Format(aranyagoconst.TimeLayout),
		ExitCode: func() int32 {
			if ctrInfo.State != nil {
				return int32(ctrInfo.State.ExitCode)
			}
			return 0
		}(),
		RestartCount: int32(ctrInfo.RestartCount),
	}
}

func (r *dockerRuntime) doHookActions(
	ctx context.Context,
	ctrID string,
	hook *runtimepb.ContainerAction,
) *aranyagopb.ErrorMsg {
	switch action := hook.Action.(type) {
	case *runtimepb.ContainerAction_Exec_:
		if cmd := action.Exec.Command; len(cmd) > 0 {
			errCh := createExecErrCh()
			_, err := r.execInContainer(ctx, ctrID, nil, ioutil.Discard, ioutil.Discard, cmd, false, nil, errCh)
			if err != nil {
				return &aranyagopb.ErrorMsg{
					Kind:        aranyagopb.ERR_COMMON,
					Description: err.Error(),
				}
			}
			return <-errCh
		}
	case *runtimepb.ContainerAction_Http:
	case *runtimepb.ContainerAction_Socket_:
	}

	return nil
}
