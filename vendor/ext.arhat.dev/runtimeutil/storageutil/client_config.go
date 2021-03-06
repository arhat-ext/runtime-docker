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

package storageutil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

type DriverConfig struct {
	Driver string      `json:"driver" yaml:"driver"`
	Config interface{} `json:"config" yaml:"config"`
}

type ClientConfig struct {
	DriverConfig `json:",inline" yaml:",inline"`

	StdoutFile string `json:"stdoutFile" yaml:"stdoutFile"`
	StderrFile string `json:"stderrFile" yaml:"stderrFile"`

	SuccessTimeWait  time.Duration `json:"successTimeWait" yaml:"successTimeWait"`
	ExtraLookupPaths []string      `json:"extraLookupPaths" yaml:"extraLookupPaths"`
}

func (c *ClientConfig) CreateClient(ctx context.Context) (*Client, error) {
	d, err := NewDriver(c.Driver, c.DriverConfig.Config)
	if err != nil {
		return nil, err
	}

	return NewClient(ctx, d, c.SuccessTimeWait, c.ExtraLookupPaths, c.StdoutFile, c.StderrFile)
}

func (c *DriverConfig) UnmarshalJSON(data []byte) error {
	m := make(map[string]interface{})

	err := json.Unmarshal(data, &m)
	if err != nil {
		return err
	}

	return unmarshalClientConfig(m, c)
}

func (c *DriverConfig) UnmarshalYAML(value *yaml.Node) error {
	m := make(map[string]interface{})

	configData, err := yaml.Marshal(value)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(configData, &m)
	if err != nil {
		return err
	}

	return unmarshalClientConfig(m, c)
}

func unmarshalClientConfig(m map[string]interface{}, c *DriverConfig) error {
	d, ok := m["driver"]
	if !ok {
		// no driver provided
		return nil
	}

	driverName, ok := d.(string)
	if !ok {
		return fmt.Errorf("driver type must be a string")
	}

	var err error
	c.Config, err = NewConfig(driverName)
	if err != nil {
		return fmt.Errorf("unknown driver %q: %w", driverName, err)
	}

	configData, err := json.Marshal(m["config"])
	if err != nil {
		return fmt.Errorf("failed to get driver config bytes: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(configData))
	dec.DisallowUnknownFields()
	err = dec.Decode(c.Config)
	if err != nil {
		return fmt.Errorf("failed to resolve driver config %s: %w", driverName, err)
	}

	return nil
}
