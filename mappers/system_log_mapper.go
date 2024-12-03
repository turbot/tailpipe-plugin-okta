package mappers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/okta/okta-sdk-golang/v5/okta"

	"github.com/turbot/tailpipe-plugin-okta/rows"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

type SystemLogMapper struct {
}

func NewSystemLogMapper() table.Mapper[*rows.SystemLog] {
	return &SystemLogMapper{}
}

func (s SystemLogMapper) Identifier() string {
	return "okta_system_log_mapper"
}

func (s SystemLogMapper) Map(ctx context.Context, a any) (*rows.SystemLog, error) {
	systemLog := &rows.SystemLog{}
	rawRow, ok := a.(okta.LogEvent)
	if !ok {
		return nil, fmt.Errorf("expected okta.LogEvent, got %T", a)
	}

	systemLog.DisplayMessage = rawRow.DisplayMessage
	systemLog.EventType = rawRow.EventType
	systemLog.LegacyEventType = rawRow.LegacyEventType
	systemLog.Published = rawRow.Published
	systemLog.Severity = rawRow.Severity
	systemLog.Uuid = rawRow.Uuid
	systemLog.Version = rawRow.Version

	// Actor info
	actor := rawRow.GetActor()
	systemLog.ActorId = actor.Id
	systemLog.ActorAlternateId = actor.AlternateId
	systemLog.ActorDisplayName = actor.DisplayName
	systemLog.ActorType = actor.Type
	systemLog.ActorAdditionalProperties = &actor.AdditionalProperties
	systemLog.ActorDetailEntry = &actor.DetailEntry

	// AuthenticationContext info
	authContext := rawRow.GetAuthenticationContext()
	systemLog.AuthenticationProvider = authContext.AuthenticationProvider
	systemLog.AuthenticationStep = authContext.AuthenticationStep
	systemLog.CredentialProvider = authContext.CredentialProvider
	systemLog.CredentialType = authContext.CredentialType
	systemLog.ExternalSessionId = authContext.ExternalSessionId
	systemLog.Interface = authContext.Interface
	issuer, err := StructToMap(authContext.Issuer)
	if err != nil {
		return nil, err
	}
	systemLog.Issuer = &issuer
	systemLog.ActorAdditionalProperties = &authContext.AdditionalProperties

	// Client Info
	client := rawRow.GetClient()
	systemLog.ClientDevice = client.Device
	systemLog.ClientId = client.Id
	systemLog.ClientIpAddress = client.IpAddress
	systemLog.ClientZone = client.Zone
	clientGeographicalContext, err := StructToMap(client.GeographicalContext)
	if err != nil {
		return nil, err
	}
	systemLog.ClientGeographicalContext = &clientGeographicalContext
	clientUserAgent, err := StructToMap(client.UserAgent)
	if err != nil {
		return nil, err
	}
	systemLog.ClientUserAgent = &clientUserAgent
	systemLog.ClientAdditionalProperties = &client.AdditionalProperties

	// LogDebugContext info
	debugContext := rawRow.GetDebugContext()
	systemLog.DebugData = &debugContext.DebugData
	systemLog.DebugAdditionalProperties = &debugContext.AdditionalProperties

	// Outcome Info
	outcome := rawRow.GetOutcome()
	systemLog.OutcomeReason = outcome.Reason
	systemLog.OutcomeResult = outcome.Result
	systemLog.OutcomeAdditionalProperties = &outcome.AdditionalProperties

	// Request info
	request := rawRow.GetRequest()

	ipChains, err := StructArrayToMapPointerSlice(request.IpChain)
	if err != nil {
		return nil, err
	}
	systemLog.IpChain = ipChains

	// SecurityContext info
	securityContext := rawRow.GetSecurityContext()
	systemLog.AsNumber = securityContext.AsNumber
	systemLog.AsOrg = securityContext.AsOrg
	systemLog.Domain = securityContext.Domain
	systemLog.Isp = securityContext.Isp
	systemLog.IsProxy = securityContext.IsProxy

	targets, err := StructArrayToMapPointerSlice(rawRow.GetTarget())
	if err != nil {
		return nil, err
	}

	systemLog.Target = targets

	// Transaction info
	transaction := rawRow.GetTransaction()
	systemLog.TransactionId = transaction.Id
	systemLog.TransactionType = transaction.Type
	systemLog.TransactionDetail = &transaction.Detail

	systemLog.AdditionalProperties = &rawRow.AdditionalProperties

	return systemLog, nil
}

// StructToMap converts a struct to map[string]interface{}
func StructToMap(input interface{}) (map[string]interface{}, error) {
	// Marshal the struct into JSON
	data, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct: %w", err)
	}

	// Unmarshal the JSON into a map
	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON into map: %w", err)
	}

	return result, nil
}

// StructArrayToMapPointerSlice converts an array of structs to a slice of *map[string]interface{}
func StructArrayToMapPointerSlice(input interface{}) ([]*map[string]interface{}, error) {
	// Marshal the array of structs into JSON
	data, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct array: %w", err)
	}

	// Unmarshal the JSON into a slice of maps
	var result []map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON into slice of maps: %w", err)
	}

	// Convert []map[string]interface{} to []*map[string]interface{}
	var pointerSlice []*map[string]interface{}
	for _, item := range result {
		copy := item // Create a new copy to avoid reference issues
		pointerSlice = append(pointerSlice, &copy)
	}

	return pointerSlice, nil
}
