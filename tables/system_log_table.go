package tables

import (
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/okta/okta-sdk-golang/v5/okta"
	"github.com/rs/xid"

	"github.com/turbot/tailpipe-plugin-okta/config"
	"github.com/turbot/tailpipe-plugin-okta/mappers"
	"github.com/turbot/tailpipe-plugin-okta/rows"
	"github.com/turbot/tailpipe-plugin-okta/sources"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/table"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

const SystemLogTableIdentifier = "okta_system_log"

// register the table from the package init function
func init() {
	table.RegisterTable[*rows.SystemLog, *SystemLogTable]()
}

type SystemLogTable struct {
	// all tables must embed table.TableImpl
	table.TableImpl[*rows.SystemLog, *SystemLogTableConfig, *config.OktaConnection]
}

func (c *SystemLogTable) Identifier() string {
	return SystemLogTableIdentifier
}

func (c *SystemLogTable) SupportedSources() []*table.SourceMetadata[*rows.SystemLog] {
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
	ipChain := UnmarshalJSONStringToObject(row.IpChain)
	if len(ipChain) > 0 {
		row.TpDestinationIP = ipChain[len(ipChain)-1].Ip
	}
	for _, ip := range ipChain {
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

func UnmarshalJSONStringToObject(str *types.JSONString) []okta.LogIpAddress {
	if str == nil {
		return []okta.LogIpAddress{}
	}

	// Slice to hold the decoded JSON data
	var ipData []okta.LogIpAddress

	// Unmarshal the JSON into the struct
	if err := json.Unmarshal([]byte(*str), &ipData); err != nil {
		log.Fatalf("Error unmarshalling JSON: %v", err)
	}

	// Access the "ip" attribute of the first element in the array
	if len(ipData) > 0 {
		fmt.Println("IP Address:", ipData[0].Ip)
	} else {
		fmt.Println("No IP data found.")
	}

	return ipData
}
