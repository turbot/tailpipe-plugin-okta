package tables

type SystemLogTableConfig struct {
}

func (c *SystemLogTableConfig) Validate() error {
	return nil
}

func (c *SystemLogTableConfig) Identifier() string {
	return SystemLogTableIdentifier
}
