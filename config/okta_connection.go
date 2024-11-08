package config

import "github.com/turbot/tailpipe-plugin-sdk/parse"

type OktaConnection struct {
}

func NewOktaConnection() parse.Config {
	return &OktaConnection{}
}

func (c *OktaConnection) Validate() error {
	return nil
}
