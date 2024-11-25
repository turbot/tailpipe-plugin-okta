package config

import (
	"fmt"
)

const PluginName = "okta"

type OktaConnection struct {
	Token  *string `json:"token" hcl:"token"`
	Domain *string `json:"domain" hcl:"domain"`
}

func (c *OktaConnection) Validate() error {
	if c.Token == nil {
		return fmt.Errorf("token is required")
	}
	if c.Domain == nil {
		return fmt.Errorf("domain is required")
	}
	return nil
}

func (c *OktaConnection) Identifier() string {
	return PluginName
}
