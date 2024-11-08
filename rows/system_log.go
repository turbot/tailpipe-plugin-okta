package rows

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/okta/okta-sdk-golang/v5/okta"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
)

// SystemLog is the struct containing the enriched data for an AuditRecord
type SystemLog struct {
	// embed required enrichment fields
	enrichment.CommonFields

	// Top level property
	DisplayMessage  *string    `json:"displayMessage,omitempty"`
	EventType       *string    `json:"eventType,omitempty"`
	LegacyEventType *string    `json:"legacyEventType,omitempty"`
	Published       *time.Time `json:"published,omitempty"`
	Severity        *string    `json:"severity,omitempty"`
	Uuid            *string    `json:"uuid,omitempty"`
	Version         *string    `json:"version,omitempty"`

	// Actor fields
	ActorId                   *string             `json:"actor_id,omitempty"`
	ActorAlternateId          *string             `json:"actor_alternate_id,omitempty"`
	ActorDisplayName          *string             `json:"ActorDisplayName,omitempty"`
	ActorType                 *string             `json:"ActorType,omitempty"`
	ActorAdditionalProperties *helpers.JSONString `json:"ActorAdditionalProperties,omitempty"`
	ActorDetailEntry          *helpers.JSONString `json:"ActorDetailEntry,omitempty"`

	// AuthenticationContext fields
	AuthenticationProvider             *string             `json:"authenticationProvider,omitempty"`
	AuthenticationStep                 *int32              `json:"authenticationStep,omitempty"`
	CredentialProvider                 *string             `json:"credentialProvider,omitempty"`
	CredentialType                     *string             `json:"credentialType,omitempty"`
	ExternalSessionId                  *string             `json:"externalSessionId,omitempty"`
	Interface                          *string             `json:"interface,omitempty"`
	Issuer                             *helpers.JSONString `json:"issuer,omitempty"`
	AuthenticationAdditionalProperties *helpers.JSONString

	// Client fields
	ClientDevice               *string             `json:"device,omitempty"`
	ClientGeographicalContext  *helpers.JSONString `json:"geographicalContext,omitempty"`
	ClientId                   *string             `json:"id,omitempty"`
	ClientIpAddress            *string             `json:"ipAddress,omitempty"`
	ClientUserAgent            *helpers.JSONString `json:"userAgent,omitempty"`
	ClientZone                 *string             `json:"zone,omitempty"`
	ClientAdditionalProperties *helpers.JSONString

	// LogDebugContext fields
	DebugData                 *helpers.JSONString `json:"debugData,omitempty"`
	DebugAdditionalProperties *helpers.JSONString

	// Outcome fields
	OutcomeReason               *string `json:"Outcome_reason,omitempty"`
	OutcomeResult               *string `json:"Outcome_result,omitempty"`
	OutcomeAdditionalProperties *helpers.JSONString

	// Request fields
	IpChain *helpers.JSONString

	// SecurityContext field
	AsNumber *int32  `json:"asNumber,omitempty"`
	AsOrg    *string `json:"asOrg,omitempty"`
	Domain   *string `json:"domain,omitempty"`
	Isp      *string `json:"isp,omitempty"`
	IsProxy  *bool   `json:"isProxy,omitempty"`

	Target *helpers.JSONString `json:"target,omitempty"`

	// Transaction fields
	TransactionId     *string             `json:"TransactionId,omitempty"`
	TransactionType   *string             `json:"TransactionType,omitempty"`
	TransactionDetail *helpers.JSONString `json:"TransactionDetail,omitempty"`

	AdditionalProperties *helpers.JSONString
}

func (a *SystemLog) MapFromOktaSystemLog(item okta.LogEvent) error {

	a.DisplayMessage = item.DisplayMessage
	a.EventType = item.EventType
	a.LegacyEventType = item.LegacyEventType
	a.Published = item.Published
	a.Severity = item.Severity
	a.Uuid = item.Uuid
	a.Version = item.Version

	// Actor info
	actor := item.GetActor()
	a.ActorId = actor.Id
	a.ActorAlternateId = actor.AlternateId
	a.ActorDisplayName = actor.DisplayName
	a.ActorType = actor.Type
	a.ActorAdditionalProperties = marshalAnyFormatToJSONString(actor.AdditionalProperties)
	a.ActorDetailEntry = marshalAnyFormatToJSONString(actor.DetailEntry)

	// AuthenticationContext info
	aContext := item.GetAuthenticationContext()
	a.AuthenticationProvider = aContext.AuthenticationProvider
	a.AuthenticationStep = aContext.AuthenticationStep
	a.CredentialProvider = aContext.CredentialProvider
	a.CredentialType = aContext.CredentialType
	a.ExternalSessionId = aContext.ExternalSessionId
	a.Interface = aContext.Interface
	a.Issuer = marshalAnyFormatToJSONString(aContext.Issuer)
	a.ActorAdditionalProperties = marshalAnyFormatToJSONString(aContext.AdditionalProperties)

	// Client Info
	c := item.GetClient()
	a.ClientDevice = c.Device
	a.ClientId = c.Id
	a.ClientIpAddress = c.IpAddress
	a.ClientZone = c.Zone
	a.ClientGeographicalContext = marshalAnyFormatToJSONString(c.GeographicalContext)
	a.ClientUserAgent = marshalAnyFormatToJSONString(c.UserAgent)
	a.ClientAdditionalProperties = marshalAnyFormatToJSONString(c.AdditionalProperties)

	// LogDebugContext info
	dd := item.GetDebugContext()
	a.DebugData = marshalAnyFormatToJSONString(dd.DebugData)
	a.DebugAdditionalProperties = marshalAnyFormatToJSONString(dd.AdditionalProperties)

	// Outcome Info
	oc := item.GetOutcome()
	a.OutcomeReason = oc.Reason
	a.OutcomeResult = oc.Result
	a.OutcomeAdditionalProperties = marshalAnyFormatToJSONString(oc.AdditionalProperties)

	// Request info
	req := item.GetRequest()
	a.IpChain = marshalAnyFormatToJSONString(req.IpChain)

	// SecurityContext info
	sc := item.GetSecurityContext()
	a.AsNumber = sc.AsNumber
	a.AsOrg = sc.AsOrg
	a.Domain = sc.Domain
	a.Isp = sc.Isp
	a.IsProxy = sc.IsProxy

	a.Target = marshalAnyFormatToJSONString(item.GetTarget())

	// Transaction info
	t := item.GetTransaction()
	a.TransactionId = t.Id
	a.TransactionType = t.Type
	a.TransactionDetail = marshalAnyFormatToJSONString(t.Detail)

	a.AdditionalProperties = marshalAnyFormatToJSONString(item.AdditionalProperties)

	return nil
}

func marshalAnyFormatToJSONString(data any) *helpers.JSONString {
	if data == nil {
		return nil
	}
	s, err := json.Marshal(data)
	if err != nil {
		panic(fmt.Errorf("error marshalling row data: %w", err))
	}
	dataJsonString := helpers.JSONString(s)

	return &dataJsonString
}

// TODO: Need to work on how to filter the IPs from the type *helpers.JSONString

// func UnmarshalToJSONString(str *helpers.JSONString, dataType string, property string, numberOfproperty string) (result interface{}, err error) {
// 	var res interface{}
// 	data := []byte{}
// 	err = str.UnmarshalJSON(data)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if err := json.Unmarshal(data, &res); err != nil {
// 		return nil, fmt.Errorf("error unmarshalling JSON: %w", err)
// 	}

// 	switch dataType {
// 	case "map":
// 		r := res.(map[string]interface{})
// 		return r[property], nil
// 	case "slice":
// 		var mapSlice []interface{}
// 		for _, item := range res.([]interface{}) {
// 			if mapItem, ok := item.(map[string]interface{}); ok {
// 				if numberOfproperty == "single" {
// 					return mapItem[property], nil
// 				}
// 				mapSlice = append(mapSlice, mapItem[property])
// 			}
// 		}
// 		return mapSlice, nil
// 	default:
// 		// Do nothing
// 	}

// 	return nil, nil
// }
