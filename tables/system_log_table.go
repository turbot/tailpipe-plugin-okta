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
	if row.ClientIpAddress != nil {
		row.TpSourceIP = row.ClientIpAddress
		row.TpIps = append(row.TpIps, *row.ClientIpAddress)
	}
	// ipChain := UnmarshalJSONStringToObject(row.IpChain)
	if len(row.IpChain.IpChain) > 0 {
		row.TpDestinationIP = row.IpChain.IpChain[len(row.IpChain.IpChain)-1].Ip
	}
	for _, ip := range row.IpChain.IpChain {
		if !slices.Contains(row.TpIps, *ip.Ip) {
			row.TpIps = append(row.TpIps, *ip.Ip)
		}
	}

	// User enrichment
	if row.ActorId != nil {
		row.TpUsernames = append(row.TpUsernames, *row.ActorId)
	}
	if row.ActorDisplayName != nil {
		row.TpUsernames = append(row.TpUsernames, *row.ActorDisplayName)
	}
	if row.ActorAlternateId != nil {
		row.TpUsernames = append(row.TpUsernames, *row.ActorAlternateId)
	}

	// Domain enrichment
	if row.Domain != nil {
		row.TpDomains = append(row.TpDomains, *row.Domain)
	}

	return row, nil
}
