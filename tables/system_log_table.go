package tables

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-okta/config"
	"github.com/turbot/tailpipe-plugin-okta/rows"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/table"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

const SystemLogTableIdentifier = "okta_system_log"

// register the table from the package init function
func init() {
	table.RegisterTable(NewSystemLogTable)
}

type SystemLogTable struct {
	// all tables must embed table.TableImpl
	table.TableImpl[*rows.SystemLog, *SystemLogTableConfig, *config.OktaConnection]
}

func NewSystemLogTable() table.Enricher[*rows.SystemLog] {
	return &SystemLogTable{}
}

func (c *SystemLogTable) Identifier() string {
	return SystemLogTableIdentifier
}

// GetRowSchema implements Table
// return an instance of the row struct
func (c *SystemLogTable) GetRowSchema() types.RowStruct {
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
	if sourceEnrichmentFields.TpSourceName == nil {
		return nil, fmt.Errorf("SystemLogTable EnrichRow called with TpSourceName unset in sourceEnrichmentFields")
	}

	row.CommonFields = *sourceEnrichmentFields

	// id & Hive fields
	row.TpID = xid.New().String()
	row.TpIndex = *row.SubDomain
	row.TpTimestamp = *row.Published
	row.TpIngestTimestamp = time.Now()
	row.TpDate = row.Published.Truncate(24 * time.Hour)

	// Source Ip
	ipDatails := UnmarshalJSONStringToObject(row.IpChain)

	if len(ipDatails) > 0 && ipDatails[0].IP != "" {
		row.TpSourceIP = &ipDatails[0].IP
	}

	// Timestamps
	row.TpTimestamp = *row.Published
	row.TpIngestTimestamp = *row.Published

	row.TpUsernames = append(row.TpUsernames, *row.ActorDisplayName, *row.ActorId)

	return row, nil
}

func UnmarshalJSONStringToObject(str *types.JSONString) []IPData {
	if str == nil {
		return []IPData{}

	}

	// Slice to hold the decoded JSON data
	var ipData []IPData

	// Unmarshal the JSON into the struct
	if err := json.Unmarshal([]byte(*str), &ipData); err != nil {
		log.Fatalf("Error unmarshalling JSON: %v", err)
	}

	// Access the "ip" attribute of the first element in the array
	if len(ipData) > 0 {
		fmt.Println("IP Address:", ipData[0].IP)
	} else {
		fmt.Println("No IP data found.")
	}

	return ipData
}

// Define the structure that matches your JSON
type Geolocation struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type GeographicalContext struct {
	City        string      `json:"city"`
	Country     string      `json:"country"`
	Geolocation Geolocation `json:"geolocation"`
	PostalCode  string      `json:"postalCode"`
	State       string      `json:"state"`
}

type IPData struct {
	GeographicalContext GeographicalContext `json:"geographicalContext"`
	IP                  string              `json:"ip"`
	Version             string              `json:"version"`
}
