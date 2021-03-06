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

package cmd

import (
	"context"
	"fmt"

	"arhat.dev/arhat-proto/arhatgopb"
	"arhat.dev/libext"
	"arhat.dev/libext/codec"
	"arhat.dev/libext/extruntime"
	"arhat.dev/pkg/log"
	"ext.arhat.dev/runtimeutil/storageutil"
	"github.com/spf13/cobra"

	"ext.arhat.dev/runtime-docker/pkg/conf"
	"ext.arhat.dev/runtime-docker/pkg/constant"
	"ext.arhat.dev/runtime-docker/pkg/runtime"
)

func NewRuntimeDockerCmd() *cobra.Command {
	var (
		appCtx       context.Context
		configFile   string
		config       = new(conf.Config)
		cliLogConfig = new(log.Config)
	)

	runtimeDockerCmd := &cobra.Command{
		Use:           "runtime-docker",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Use == "version" {
				return nil
			}

			var err error
			appCtx, err = conf.ReadConfig(cmd, &configFile, cliLogConfig, config)
			if err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(appCtx, config)
		},
	}

	flags := runtimeDockerCmd.PersistentFlags()

	flags.StringVarP(&configFile, "config", "c", constant.DefaultAppConfigFile,
		"path to the config file")
	flags.AddFlagSet(conf.FlagsForApp("", &config.App))
	flags.AddFlagSet(conf.FlagsForRuntime("runtime.", &config.Runtime))
	flags.AddFlagSet(storageutil.FlagsForClient("storageutil.", &config.Storage))

	return runtimeDockerCmd
}

func run(appCtx context.Context, config *conf.Config) error {
	logger := log.Log.WithName("App")

	endpoint := config.App.ExtensionHubURL

	tlsConfig, err := config.App.TLS.GetTLSConfig(false)
	if err != nil {
		return fmt.Errorf("failed to create tls config: %w", err)
	}

	c, ok := codec.Get(arhatgopb.CODEC_PROTOBUF)
	if !ok {
		return fmt.Errorf("protobuf codec not found")
	}

	client, err := libext.NewClient(
		appCtx,
		arhatgopb.EXTENSION_RUNTIME,
		"docker",
		c,
		nil,
		endpoint,
		tlsConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to create extension client: %w", err)
	}

	storageClient, err := config.Storage.CreateClient(appCtx)
	if err != nil {
		return err
	}

	rt, err := runtime.NewDockerRuntime(
		appCtx, logger.WithName("runtime"), storageClient, &config.Runtime,
	)
	if err != nil {
		return err
	}

	ctrl, err := libext.NewController(appCtx, log.Log.WithName("controller"), c.Marshal,
		extruntime.NewHandler(log.Log.WithName("handler"), config.App.MaxDataMessagePayload, rt),
	)
	if err != nil {
		return fmt.Errorf("failed to create extension controller: %w", err)
	}

	err = ctrl.Start()
	if err != nil {
		return fmt.Errorf("failed to start controller: %w", err)
	}

	logger.I("running")
	for {
		select {
		case <-appCtx.Done():
			return nil
		default:
			err = client.ProcessNewStream(ctrl.RefreshChannels())
			if err != nil {
				logger.I("error happened when processing data stream", log.Error(err))
			}
		}
	}
}
