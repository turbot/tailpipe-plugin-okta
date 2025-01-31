package system_log

import (
	"slices"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/turbot/tailpipe-plugin-okta/sources/system_log_api"
	"github.com/turbot/tailpipe-plugin-sdk/schema"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const SystemLogTableIdentifier = "okta_system_log"

type SystemLogTable struct {
}

func (c *SystemLogTable) Identifier() string {
	return SystemLogTableIdentifier
}

func (c *SystemLogTable) GetSourceMetadata() []*table.SourceMetadata[*SystemLog] {
	return []*table.SourceMetadata[*SystemLog]{
		{
			SourceName: system_log_api.SystemLogAPISourceIdentifier,
			Mapper:     &SystemLogMapper{},
		},
	}
}

func (c *SystemLogTable) EnrichRow(row *SystemLog, sourceEnrichmentFields schema.SourceEnrichment) (*SystemLog, error) {
	row.CommonFields = sourceEnrichmentFields.CommonFields

	var subDomain string
	if row.CommonFields.TpSourceLocation != nil {
		subDomain = strings.Split(strings.Replace(*row.CommonFields.TpSourceLocation, "https://", "", 2), "/")[0]
	}

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
