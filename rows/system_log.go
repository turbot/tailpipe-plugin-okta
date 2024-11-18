package rows

import (
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/types"
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
	ActorId                   *string           `json:"actor_id,omitempty"`
	ActorAlternateId          *string           `json:"actor_alternate_id,omitempty"`
	ActorDisplayName          *string           `json:"actor_display_name,omitempty"`
	ActorType                 *string           `json:"actor_type,omitempty"`
	ActorAdditionalProperties *types.JSONString `json:"actor_additional_properties,omitempty"`
	ActorDetailEntry          *types.JSONString `json:"actor_detail_entry,omitempty"`

	// AuthenticationContext fields
	AuthenticationProvider             *string           `json:"authentication_provider,omitempty"`
	AuthenticationStep                 *int32            `json:"authentication_step,omitempty"`
	CredentialProvider                 *string           `json:"credential_provider,omitempty"`
	CredentialType                     *string           `json:"credential_type,omitempty"`
	ExternalSessionId                  *string           `json:"external_session_id,omitempty"`
	Interface                          *string           `json:"interface,omitempty"`
	Issuer                             *types.JSONString `json:"issuer,omitempty"`
	AuthenticationAdditionalProperties *types.JSONString `json:"authentication_additional_properties,omitempty"`

	// Client fields
	ClientDevice               *string           `json:"client_device,omitempty"`
	ClientGeographicalContext  *types.JSONString `json:"client_geographical_context,omitempty"`
	ClientId                   *string           `json:"client_id,omitempty"`
	ClientIpAddress            *string           `json:"client_ip_address,omitempty"`
	ClientUserAgent            *types.JSONString `json:"client_user_agent,omitempty"`
	ClientZone                 *string           `json:"client_zone,omitempty"`
	ClientAdditionalProperties *types.JSONString `json:"client_additional_properties,omitempty"`

	// LogDebugContext fields
	DebugData                 *types.JSONString `json:"debug_data,omitempty"`
	DebugAdditionalProperties *types.JSONString `json:"debug_additional_properties,omitempty"`

	// Outcome fields
	OutcomeReason               *string           `json:"outcome_reason,omitempty"`
	OutcomeResult               *string           `json:"outcome_result,omitempty"`
	OutcomeAdditionalProperties *types.JSONString `json:"outcome_additional_properties,omitempty"`

	// Request fields
	IpChain *types.JSONString `json:"ip_chain,omitempty"`

	// SecurityContext field
	AsNumber *int32            `json:"as_number,omitempty"`
	AsOrg    *string           `json:"as_org,omitempty"`
	Domain   *string           `json:"domain,omitempty"`
	Isp      *string           `json:"isp,omitempty"`
	IsProxy  *bool             `json:"is_proxy,omitempty"`
	Target   *types.JSONString `json:"target,omitempty"`

	// Transaction fields
	TransactionId        *string           `json:"transaction_id,omitempty"`
	TransactionType      *string           `json:"transaction_type,omitempty"`
	TransactionDetail    *types.JSONString `json:"transaction_detail,omitempty"`
	AdditionalProperties *types.JSONString `json:"additional_properties,omitempty"`
}
