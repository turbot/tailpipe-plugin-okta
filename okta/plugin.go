package okta

import (
	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/tailpipe-plugin-okta/config"
	"github.com/turbot/tailpipe-plugin-okta/sources"
	"github.com/turbot/tailpipe-plugin-okta/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/table"
	"log/slog"
	//"time"
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

	slog.Info("Auth0 Plugin starting")
	
	p := &Plugin{
		PluginImpl: plugin.NewPluginImpl("okta", config.NewOktaConnection),
	}

	// register the tables, sources and mappers that we provide
	resources := &plugin.ResourceFunctions{
		Tables:  []func() table.Table{tables.NewSystemLogTable},
		Sources: []func() row_source.RowSource{sources.NewSystemLogAPISource},
	}

	if err := p.RegisterResources(resources); err != nil {
		return nil, err
	}

	return p, nil
}
