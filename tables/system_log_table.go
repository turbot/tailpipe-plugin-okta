package tables

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/turbot/tailpipe-plugin-okta/mappers"
	"github.com/turbot/tailpipe-plugin-okta/rows"
	"github.com/turbot/tailpipe-plugin-okta/sources"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const SystemLogTableIdentifier = "okta_system_log"

// register the table from the package init function
func init() {
	// Register the table, with type parameters:
	// 1. row struct
	// 2. table config struct
	// 3. table implementation
	table.RegisterTable[*rows.SystemLog, *SystemLogTableConfig, *SystemLogTable]()
}

type SystemLogTable struct {
}

func (c *SystemLogTable) Identifier() string {
	return SystemLogTableIdentifier
}

func (c *SystemLogTable) SupportedSources(_ *SystemLogTableConfig) []*table.SourceMetadata[*rows.SystemLog] {
	return []*table.SourceMetadata[*rows.SystemLog]{
		{
			SourceName: sources.SystemLogAPISourceIdentifier,
			MapperFunc: mappers.NewSystemLogMapper,
		},
	}
}

func (c *SystemLogTable) EnrichRow(row *rows.SystemLog, sourceEnrichmentFields *enrichment.CommonFields) (*rows.SystemLog, error) {
	// we expect sourceEnrichmentFields to be set
	if sourceEnrichmentFields == nil {
		return nil, fmt.Errorf("SystemLogTable EnrichRow called with nil sourceEnrichmentFields")
	}
	// we expect name to be set by the Source
	if sourceEnrichmentFields.TpSourceName == nil {
		return nil, fmt.Errorf("SystemLogTable EnrichRow called with TpSourceName unset in sourceEnrichmentFields")
	}

	row.CommonFields = *sourceEnrichmentFields

	subDomain := strings.Split(strings.Replace(*sourceEnrichmentFields.TpSourceLocation, "https://", "", 2), "/")[0]

	// id & Hive fields
	row.TpID = xid.New().String()
	row.TpIndex = subDomain
	row.TpTimestamp = *row.Published
	row.TpIngestTimestamp = time.Now()
	row.TpDate = row.Published.Truncate(24 * time.Hour)

	// IP enrichment
	if row.Client != nil {
		ipAddr := row.Client.IpAddress
		row.TpSourceIP = ipAddr
		row.TpIps = append(row.TpIps, *ipAddr)
	}
	if len(row.Request.IpChain) > 0 {
		row.TpDestinationIP = row.Request.IpChain[len(row.Request.IpChain)-1].Ip
	}
	for _, ip := range row.Request.IpChain {
		if !slices.Contains(row.TpIps, *ip.Ip) {
			row.TpIps = append(row.TpIps, *ip.Ip)
		}
	}

	// User enrichment
	if row.Actor != nil {
		if row.Actor.DisplayName != nil {
			row.TpUsernames = append(row.TpUsernames, *row.Actor.DisplayName)
		}
		if row.Actor.Id != nil {
			row.TpUsernames = append(row.TpUsernames, *row.Actor.Id)
		}
		if row.Actor.AlternateId != nil {
			row.TpUsernames = append(row.TpUsernames, *row.Actor.AlternateId)
		}
	}

	// Domain enrichment
	if row.SecurityContext.Domain != nil {
		row.TpDomains = append(row.TpDomains, *row.SecurityContext.Domain)
	}

	return row, nil
}
