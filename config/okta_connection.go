package config

const PluginName = "okta"

type OktaConnection struct {
}

func (c *OktaConnection) Validate() error {
	return nil
}

func (c *OktaConnection) Identifier() string {
	return PluginName
}
