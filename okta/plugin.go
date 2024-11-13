package okta

import (
	"log/slog"

	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/tailpipe-plugin-okta/config"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"

	// reference the table package to ensure that the tables are registered by the init functions
	_ "github.com/turbot/tailpipe-plugin-okta/tables"
	_ "github.com/turbot/tailpipe-plugin-okta/sources"
)

type Plugin struct {
	plugin.PluginImpl
}

func NewPlugin() (_ plugin.TailpipePlugin, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = helpers.ToError(r)
		}
	}()

	slog.Info("Okta Plugin starting")

	p := &Plugin{
		PluginImpl: plugin.NewPluginImpl("okta", config.NewOktaConnection),
	}

	// initialise table factory
	if err := table.Factory.Init(); err != nil {
		return nil, err
	}

	return p, nil
}
