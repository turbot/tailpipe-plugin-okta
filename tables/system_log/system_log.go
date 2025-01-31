package system_log

import (
	"time"

	"github.com/okta/okta-sdk-golang/v5/okta"

	"github.com/turbot/tailpipe-plugin-sdk/schema"
)

// SystemLog is the struct containing the enriched data for an AuditRecord
type SystemLog struct {
	// embed required enrichment fields
	schema.CommonFields

	Uuid                  *string                             `json:"uuid,omitempty"`
	DisplayMessage        *string                             `json:"display_message,omitempty"`
	EventType             *string                             `json:"event_type,omitempty"`
	LegacyEventType       *string                             `json:"legacy_event_type,omitempty"`
	Published             *time.Time                          `json:"published,omitempty"`
	Severity              *string                             `json:"severity,omitempty"`
	Version               *string                             `json:"version,omitempty"`
	SubDomain             *string                             `json:"sub_domain,omitempty"`
	Actor                 *OktaSystemLogActor                 `json:"actor,omitempty"`
	AuthenticationContext *OktaSystemLogAuthenticationContext `json:"authentication_context,omitempty"`
	Client                *OktaSystemLogClient                `json:"client,omitempty"`
	DebugContext          *OktaSystemLogDebugContext          `json:"debug_context,omitempty"`
	Outcome               *OktaSystemLogOutcome               `json:"outcome,omitempty"`
	Request               *OktaSystemLogRequest               `json:"request,omitempty"`
	Target                []okta.LogTarget                    `json:"target,omitempty" parquet:"type=JSON"`
	SecurityContext       *OktaSystemLogSecurityContext       `json:"security_context,omitempty"`
	Transaction           *OktaSystemLogTransaction           `json:"transaction,omitempty"`
	AdditionalProperties  *map[string]interface{}             `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

// Actor
type OktaSystemLogActor struct {
	AlternateId          *string                `json:"alternate_id,omitempty"`
	DetailEntry          map[string]interface{} `json:"detail_entry,omitempty" parquet:"type=JSON"`
	DisplayName          *string                `json:"display_name,omitempty"`
	Id                   *string                `json:"id,omitempty"`
	Type                 *string                `json:"type,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

// AuthenticationContext
type OktaSystemLogAuthenticationContext struct {
	AuthenticationProvider *string                `json:"authentication_provider,omitempty"`
	AuthenticationStep     *int32                 `json:"authentication_step,omitempty"`
	CredentialProvider     *string                `json:"credential_provider,omitempty"`
	CredentialType         *string                `json:"credential_type,omitempty"`
	ExternalSessionId      *string                `json:"external_session_id,omitempty"`
	Interface              *string                `json:"interface,omitempty"`
	Issuer                 *LogIssuer             `json:"issuer,omitempty"`
	AdditionalProperties   map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type LogIssuer struct {
	Id                   *string                `json:"id,omitempty"`
	Type                 *string                `json:"type,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

// Client
type OktaSystemLogClient struct {
	Device               *string                 `json:"device,omitempty"`
	GeographicalContext  *LogGeographicalContext `json:"geographical_context,omitempty"`
	Id                   *string                 `json:"id,omitempty"`
	IpAddress            *string                 `json:"ip_address,omitempty"`
	UserAgent            *LogUserAgent           `json:"user_agent,omitempty"`
	Zone                 *string                 `json:"zone,omitempty"`
	AdditionalProperties map[string]interface{}  `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type LogGeographicalContext struct {
	City                 *string                `json:"city,omitempty"`
	Country              *string                `json:"country,omitempty"`
	Geolocation          *LogGeolocation        `json:"geolocation,omitempty"`
	PostalCode           *string                `json:"postal_code,omitempty"`
	State                *string                `json:"state,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type LogGeolocation struct {
	Lat                  *float64               `json:"lat,omitempty"`
	Lon                  *float64               `json:"lon,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type LogUserAgent struct {
	Browser              *string                `json:"browser,omitempty"`
	Os                   *string                `json:"os,omitempty"`
	RawUserAgent         *string                `json:"raw_user_agent,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

// DebugContext
type OktaSystemLogDebugContext struct {
	DebugData            map[string]interface{} `json:"debug_data,omitempty" parquet:"type=JSON"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

// Outcome
type OktaSystemLogOutcome struct {
	Reason               *string                `json:"reason,omitempty"`
	Result               *string                `json:"result,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

// Request
type OktaSystemLogRequest struct {
	IpChain              []okta.LogIpAddress    `json:"ip_chain,omitempty" parquet:"type=JSON"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

// SecurityContext
type OktaSystemLogSecurityContext struct {
	AsNumber             *int32                 `json:"as_number,omitempty"`
	AsOrg                *string                `json:"as_org,omitempty"`
	Domain               *string                `json:"domain,omitempty"`
	Isp                  *string                `json:"isp,omitempty"`
	IsProxy              *bool                  `json:"is_proxy,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

// Transaction
type OktaSystemLogTransaction struct {
	Detail               map[string]interface{} `json:"detail,omitempty" parquet:"type=JSON"`
	Id                   *string                `json:"id,omitempty"`
	Type                 *string                `json:"type,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}
