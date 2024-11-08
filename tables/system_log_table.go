package tables

import (
	"fmt"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-okta/config"
	"github.com/turbot/tailpipe-plugin-okta/rows"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const SystemLogTableIdentifier = "okta_system_log"

type SystemLogTable struct {
	// all tables must embed table.TableImpl
	table.TableImpl[*rows.SystemLog, *SystemLogTableConfig, *config.OktaConnection]
}

func NewSystemLogTable() table.Table {
	return &SystemLogTable{}
}

func (c *SystemLogTable) Identifier() string {
	return SystemLogTableIdentifier
}

// GetRowSchema implements Table
// return an instance of the row struct
func (c *SystemLogTable) GetRowSchema() any {
	return rows.SystemLog{}
}

func (c *SystemLogTable) GetConfigSchema() parse.Config {
	return &SystemLogTableConfig{}
}

func (c *SystemLogTable) EnrichRow(row *rows.SystemLog, sourceEnrichmentFields *enrichment.CommonFields) (*rows.SystemLog, error) {
	// we expect sourceEnrichmentFields to be set
	if sourceEnrichmentFields == nil {
		return nil, fmt.Errorf("SystemLogTable EnrichRow called with nil sourceEnrichmentFields")
	}
	// we expect name to be set by the Source
	if sourceEnrichmentFields.TpSourceName == "" {
		return nil, fmt.Errorf("SystemLogTable EnrichRow called with TpSourceName unset in sourceEnrichmentFields")
	}

	row.CommonFields = *sourceEnrichmentFields

	// id & Hive fields
	row.TpID = xid.New().String()
	row.TpIndex = *row.Uuid
	row.TpDate = row.Published.Format("2006-01-02")

	// Timestamps
	row.TpTimestamp = helpers.UnixMillis(row.Published.UnixNano() / int64(time.Millisecond))
	row.TpIngestTimestamp = helpers.UnixMillis(time.Now().UnixNano() / int64(time.Millisecond))

	row.TpUsernames = append(row.TpUsernames, *row.ActorDisplayName, *row.ActorId)

	return row, nil
}
