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
	"strconv"

	"arhat.dev/aranya-proto/aranyagopb"
	"arhat.dev/libext/types"
	"arhat.dev/pkg/log"
	dockertype "github.com/docker/docker/api/types"
	dockercopy "github.com/docker/docker/pkg/stdcopy"

	"ext.arhat.dev/runtimeutil"
)

func (r *dockerRuntime) Exec(
	ctx context.Context,
	podUID, container string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	command []string,
	tty bool,
	errCh chan<- *aranyagopb.ErrorMsg,
) (types.ResizeHandleFunc, error) {
	logger := r.logger.WithFields(
		log.String("uid", podUID),
		log.String("container", container),
		log.String("action", "exec"),
	)
	logger.D("exec in pod container")

	ctr, err := r.findContainer(ctx, podUID, container)
	if err != nil {
		return nil, err
	}

	return r.execInContainer(
		ctx, ctr.ID, stdin, stdout, stderr, command, tty, nil, errCh,
	)
}

func (r *dockerRuntime) Attach(
	ctx context.Context,
	podUID, container string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	errCh chan<- *aranyagopb.ErrorMsg,
) (types.ResizeHandleFunc, error) {
	logger := r.logger.WithFields(
		log.String("action", "attach"),
		log.String("uid", podUID),
		log.String("container", container),
	)
	logger.D("attach to pod container")

	ctr, err := r.findContainer(ctx, podUID, container)
	if err != nil {
		return nil, err
	}

	ctx, cancelAttach := r.ActionContext(ctx)
	defer cancelAttach()

	attachResp, err := r.runtimeClient.ContainerAttach(ctx, ctr.ID, dockertype.ContainerAttachOptions{
		Stream: true,
		Stdin:  stdin != nil,
		Stdout: stdout != nil,
		Stderr: stderr != nil,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach container: %w", err)
	}
	go func() {
		defer func() {
			defer func() {
				_ = recover()
			}()

			_ = attachResp.Conn.Close()

			close(errCh)
		}()

		var err2 error
		if stderr != nil {
			_, err2 = dockercopy.StdCopy(stdout, stderr, attachResp.Reader)
		} else {
			_, err2 = io.Copy(stdout, attachResp.Reader)
		}

		if err2 != nil {
			select {
			case <-ctx.Done():
			case errCh <- &aranyagopb.ErrorMsg{
				Kind:        aranyagopb.ERR_COMMON,
				Description: err2.Error(),
				Code:        0,
			}:
			}
		}
	}()

	if stdin != nil {
		go func() {
			defer func() {
				_ = recover()
			}()

			_, err2 := io.Copy(attachResp.Conn, stdin)
			if err2 != nil {
				select {
				case <-ctx.Done():
				case errCh <- &aranyagopb.ErrorMsg{
					Kind:        aranyagopb.ERR_COMMON,
					Description: err2.Error(),
					Code:        0,
				}:
				}
			}
		}()
	}

	return func(cols, rows uint32) {
		err2 := r.runtimeClient.ContainerResize(ctx, ctr.ID, dockertype.ResizeOptions{
			Height: uint(rows),
			Width:  uint(cols),
		})
		if err2 != nil {
			logger.I("failed to resize tty", log.Error(err2))
		}
	}, nil
}

func (r *dockerRuntime) Logs(
	ctx context.Context,
	options *aranyagopb.LogsCmd,
	stdout, stderr io.Writer,
) error {
	logger := r.logger.WithFields(
		log.String("action", "log"),
		log.String("uid", options.PodUid),
		log.Any("options", options),
	)
	logger.D("fetching pod container logs")

	ctr, err := r.findContainer(ctx, options.PodUid, options.Container)
	if err != nil {
		return err
	}

	var since, tail string
	if options.Since != "" {
		since = options.Since
	}

	if options.TailLines > 0 {
		tail = strconv.FormatInt(options.TailLines, 10)
	}

	logReader, err := r.runtimeClient.ContainerLogs(ctx, ctr.ID, dockertype.ContainerLogsOptions{
		ShowStdout: stdout != nil,
		ShowStderr: stderr != nil,
		Since:      since,
		Timestamps: options.Timestamp,
		Follow:     options.Follow,
		Tail:       tail,
		Details:    false,
	})
	if err != nil {
		return fmt.Errorf("failed to read container logs: %w", err)
	}
	defer func() { _ = logReader.Close() }()

	_, err = dockercopy.StdCopy(stdout, stderr, logReader)
	if err != nil {
		return fmt.Errorf("exception happened when reading logs: %w", err)
	}

	return nil
}

func (r *dockerRuntime) PortForward(
	ctx context.Context,
	podUID string,
	protocol string,
	port int32,
	upstream io.Reader,
	downstream io.Writer,
) error {
	logger := r.logger.WithFields(
		log.String("action", "portforward"),
		log.String("proto", protocol),
		log.Int32("port", port),
		log.String("uid", podUID),
	)

	logger.D("port-forwarding to pod container")
	pauseCtr, err := r.findContainer(ctx, podUID, runtimeutil.ContainerNamePause)
	if err != nil {
		return err
	}

	// TODO: fix address discovery
	if pauseCtr.NetworkSettings == nil {
		return fmt.Errorf("failed to find network settings: %w", err)
	}

	address := ""
	for name, endpoint := range pauseCtr.NetworkSettings.Networks {
		if name == "bridge" {
			address = endpoint.IPAddress
			break
		}
	}

	if address == "" {
		return fmt.Errorf("failed to find container bridge address: %w", err)
	}

	ctx, cancel := r.ActionContext(ctx)
	defer cancel()

	return runtimeutil.PortForward(ctx, address, protocol, port, upstream, downstream)
}
