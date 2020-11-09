package conf

import (
	"ext.arhat.dev/runtime-docker/pkg/constant"
	"github.com/spf13/pflag"
	"path/filepath"
	"runtime"
	"time"
)

type RuntimeConfig struct {
	DataDir string `json:"dataDir" yaml:"dataDir"`

	PauseImage   string   `json:"pauseImage" yaml:"pauseImage"`
	PauseCommand []string `json:"pauseCommand" yaml:"pauseCommand"`

	Endpoint    string        `json:"endpoint" yaml:"endpoint"`
	DialTimeout time.Duration `json:"dialTimeout" yaml:"dialTimeout"`

	ImageActionTimeout time.Duration `json:"imageActionTimeout" yaml:"imageActionTimeout"`
	PodActionTimeout   time.Duration `json:"podActionTimeout" yaml:"podActionTimeout"`

	AbbotRequestSubCmd string `json:"abbotRequestSubCmd" yaml:"abbotRequestSubCmd"`
}

func FlagsForRuntime(prefix string, config *RuntimeConfig) *pflag.FlagSet {
	fs := pflag.NewFlagSet("runtime", pflag.ExitOnError)

	fs.StringVar(&config.DataDir, prefix+"dataDir",
		constant.DefaultPodDataDir, "set pod data root dir")

	fs.StringVar(&config.PauseImage, prefix+"pauseImage",
		constant.DefaultPauseImage, "set pause image to use")

	fs.StringSliceVar(&config.PauseCommand, prefix+"pauseCommand",
		[]string{constant.DefaultPauseCommand}, "set pause command to pause image")

	var endpoint string
	switch runtime.GOOS {
	case "windows":
		endpoint = constant.DefaultDockerWindowsEndpoint
	default:
		endpoint = constant.DefaultDockerUnixEndpoint
	}

	fs.StringVar(&config.Endpoint, prefix+"endpoint",
		endpoint, "set docker endpoint")

	fs.DurationVar(&config.PodActionTimeout, prefix+"dialTimeout",
		constant.DefaultDockerDialTimeout, "set image operation timeout")

	fs.DurationVar(&config.ImageActionTimeout, prefix+"imageActionTimeout",
		constant.DefaultImageActionTimeout, "set image operation timeout")

	fs.DurationVar(&config.PodActionTimeout, prefix+"podActionTimeout",
		constant.DefaultPodActionTimeout, "set image operation timeout")

	fs.StringVar(&config.AbbotRequestSubCmd, prefix+"abbotRequestSubCmd",
		"process", "set abbot sub command to process requests")

	return fs
}

func (c *RuntimeConfig) PodDir(podUID string) string {
	return filepath.Join(c.DataDir, "pods", podUID)
}

func (c *RuntimeConfig) podVolumeDir(podUID, typ, volumeName string) string {
	return filepath.Join(c.PodDir(podUID), "volumes", typ, volumeName)
}

func (c *RuntimeConfig) PodRemoteVolumeDir(podUID, volumeName string) string {
	return c.podVolumeDir(podUID, "remote", volumeName)
}

func (c *RuntimeConfig) PodBindVolumeDir(podUID, volumeName string) string {
	return c.podVolumeDir(podUID, "bind", volumeName)
}

func (c *RuntimeConfig) PodTmpfsVolumeDir(podUID, volumeName string) string {
	return c.podVolumeDir(podUID, "tmpfs", volumeName)
}

func (c *RuntimeConfig) PodResolvConfFile(podUID string) string {
	return filepath.Join(c.PodDir(podUID), "volumes", "bind", "_net", "resolv.conf")
}
