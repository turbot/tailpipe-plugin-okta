package sources

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

type SystemLogAPISourceConfig struct {
	// required to allow partial decoding
	Remain hcl.Body `hcl:",remain" json:"-"`

	Token          *string `json:"token" hcl:"token"`
	Domain         *string `json:"domain" hcl:"domain"`
	RequestTimeout *int64  `json:"request_timeout" hcl:"request_timeout"`
	MaxRetries     *int32  `json:"max_retries" hcl:"max_retries"`
	MaxBackoff     *int64  `json:"max_backoff" hcl:"max_backoff"`
}

func (c *SystemLogAPISourceConfig) Validate() error {
	if c.Token == nil {
		return fmt.Errorf("token is required")
	}
	if c.Domain == nil {
		return fmt.Errorf("domain is required")
	}
	return nil
}

func (c *SystemLogAPISourceConfig) Identifier() string {
	return SystemLogAPISourceIdentifier

}
