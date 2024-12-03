package rows

import (
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
)

// SystemLog is the struct containing the enriched data for an AuditRecord
type SystemLog struct {
	// embed required enrichment fields
	enrichment.CommonFields

	// Top level property
	DisplayMessage  *string    `json:"display_message,omitempty"`
	EventType       *string    `json:"event_type,omitempty"`
	LegacyEventType *string    `json:"legacy_event_type,omitempty"`
	Published       *time.Time `json:"published,omitempty"`
	Severity        *string    `json:"severity,omitempty"`
	Uuid            *string    `json:"uuid,omitempty"`
	Version         *string    `json:"version,omitempty"`
	SubDomain       *string    `json:"sub_domain,omitempty"`

	// Actor fields
	ActorId                   *string                 `json:"actor_id,omitempty"`
	ActorAlternateId          *string                 `json:"actor_alternate_id,omitempty"`
	ActorDisplayName          *string                 `json:"actor_display_name,omitempty"`
	ActorType                 *string                 `json:"actor_type,omitempty"`
	ActorAdditionalProperties *map[string]interface{} `json:"actor_additional_properties,omitempty" parquet:"name=actor_additional_properties, type=JSON"`
	ActorDetailEntry          *map[string]interface{} `json:"actor_detail_entry,omitempty" parquet:"name=actor_detail_entry, type=JSON"`

	// AuthenticationContext fields
	AuthenticationProvider             *string                 `json:"authentication_provider,omitempty"`
	AuthenticationStep                 *int32                  `json:"authentication_step,omitempty"`
	CredentialProvider                 *string                 `json:"credential_provider,omitempty"`
	CredentialType                     *string                 `json:"credential_type,omitempty"`
	ExternalSessionId                  *string                 `json:"external_session_id,omitempty"`
	Interface                          *string                 `json:"interface,omitempty"`
	Issuer                             *OktaAuthContextIssuer  `json:"issuer,omitempty"`
	AuthenticationAdditionalProperties *map[string]interface{} `json:"authentication_additional_properties,omitempty" parquet:"name=authentication_additional_properties, type=JSON"`

	// Client fields
	ClientDevice               *string                 `json:"client_device,omitempty"`
	ClientGeographicalContext  OktaLogClient           `json:"client_geographical_context,omitempty"`
	ClientId                   *string                 `json:"client_id,omitempty"`
	ClientIpAddress            *string                 `json:"client_ip_address,omitempty"`
	ClientUserAgent            OktaUserAgent           `json:"client_user_agent,omitempty"`
	ClientZone                 *string                 `json:"client_zone,omitempty"`
	ClientAdditionalProperties *map[string]interface{} `json:"client_additional_properties,omitempty" parquet:"name=client_additional_properties, type=JSON"`

	// LogDebugContext fields
	DebugData                 *map[string]interface{} `json:"debug_data,omitempty" parquet:"name=debug_data, type=JSON"`
	DebugAdditionalProperties *map[string]interface{} `json:"debug_additional_properties,omitempty" parquet:"name=debug_additional_properties, type=JSON"`

	// Outcome fields
	OutcomeReason               *string                 `json:"outcome_reason,omitempty"`
	OutcomeResult               *string                 `json:"outcome_result,omitempty"`
	OutcomeAdditionalProperties *map[string]interface{} `json:"outcome_additional_properties,omitempty" parquet:"name=outcome_additional_properties, type=JSON"`

	// Request fields
	IpChain OktaIpChain `json:"ip_chain,omitempty"`

	// SecurityContext field
	AsNumber *int32          `json:"as_number,omitempty"`
	AsOrg    *string         `json:"as_org,omitempty"`
	Domain   *string         `json:"domain,omitempty"`
	Isp      *string         `json:"isp,omitempty"`
	IsProxy  *bool           `json:"is_proxy,omitempty"`
	Target   []OktaLogTarget `json:"target,omitempty"`

	// Transaction fields
	TransactionId        *string                 `json:"transaction_id,omitempty"`
	TransactionType      *string                 `json:"transaction_type,omitempty"`
	TransactionDetail    *map[string]interface{} `json:"transaction_detail,omitempty" parquet:"name=transaction_detail, type=JSON"`
	AdditionalProperties *map[string]interface{} `json:"additional_properties,omitempty" parquet:"name=additional_properties, type=JSON"`
}

type OktaAuthContextIssuer struct {
	Id                   *string                 `json:"id,omitempty"`
	Type                 *string                 `json:"type,omitempty"`
	AdditionalProperties *map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type OktaLogClient struct {
	Device               *string                    `json:"device,omitempty"`
	GeographicalContext  OktaLogGeographicalContext `json:"geographicalContext,omitempty"`
	Id                   *string                    `json:"id,omitempty"`
	IpAddress            *string                    `json:"ipAddress,omitempty"`
	Zone                 *string                    `json:"zone,omitempty"`
	UserAgent            OktaUserAgent              `json:"userAgent,omitempty"`
	AdditionalProperties *map[string]interface{}    `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type OktaUserAgent struct {
	Browser              *string                `json:"browser,omitempty"`
	Os                   *string                `json:"os,omitempty"`
	RawUserAgent         *string                `json:"rawUserAgent,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type OktaLogGeographicalContext struct {
	City                 *string                `json:"city,omitempty"`
	Country              *string                `json:"country,omitempty"`
	Geolocation          *LogGeolocation        `json:"geolocation,omitempty"`
	PostalCode           *string                `json:"postalCode,omitempty"`
	State                *string                `json:"state,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

// LogGeolocation struct for LogGeolocation
type LogGeolocation struct {
	Lat                  *float64               `json:"lat,omitempty"`
	Lon                  *float64               `json:"lon,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type OktaIpChain struct {
	IpChain []LogIpAddress `json:"ipChain,omitempty"`
}

type LogIpAddress struct {
	GeographicalContext  *OktaLogGeographicalContext `json:"geographicalContext,omitempty"`
	Ip                   *string                     `json:"ip,omitempty"`
	Source               *string                     `json:"source,omitempty"`
	Version              *string                     `json:"version,omitempty"`
	AdditionalProperties map[string]interface{}      `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type OktaLogTarget struct {
	AlternateId   *string                 `json:"alternateId,omitempty"`
	ChangeDetails *LogTargetChangeDetails `json:"changeDetails,omitempty"`
	// Further details on the target
	DetailEntry map[string]interface{} `json:"detailEntry,omitempty"`
	// The display name of the target
	DisplayName *string `json:"displayName,omitempty"`
	// The ID of the target
	Id *string `json:"id,omitempty"`
	// The type of target
	Type                 *string                `json:"type,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}

type LogTargetChangeDetails struct {
	// The original properties of the target
	From map[string]interface{} `json:"from,omitempty"`
	// The updated properties of the target
	To                   map[string]interface{} `json:"to,omitempty"`
	AdditionalProperties map[string]interface{} `json:"additional_properties,omitempty" parquet:"type=JSON"`
}
