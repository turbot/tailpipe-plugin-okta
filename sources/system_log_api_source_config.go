package sources

import (
	"github.com/hashicorp/hcl/v2"
)

type SystemLogAPISourceConfig struct {
	// required to allow partial decoding
	Remain hcl.Body `hcl:",remain" json:"-"`

	RequestTimeout *int64 `json:"request_timeout" hcl:"request_timeout"`
	MaxRetries     *int32 `json:"max_retries" hcl:"max_retries"`
	MaxBackoff     *int64 `json:"max_backoff" hcl:"max_backoff"`
}

func (c *SystemLogAPISourceConfig) Validate() error {
	return nil
}

func (c *SystemLogAPISourceConfig) Identifier() string {
	return SystemLogAPISourceIdentifier

}
