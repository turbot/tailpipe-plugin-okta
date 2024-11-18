package mappers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/okta/okta-sdk-golang/v5/okta"

	"github.com/turbot/tailpipe-plugin-okta/rows"
	"github.com/turbot/tailpipe-plugin-sdk/table"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

type SystemLogMapper struct {
}

func NewSystemLogMapper() table.Mapper[*rows.SystemLog] {
	return &SystemLogMapper{}
}

func (s SystemLogMapper) Identifier() string {
	return "okta_system_log_mapper"
}

func (s SystemLogMapper) Map(ctx context.Context, a any) ([]*rows.SystemLog, error) {
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
	systemLog.ActorAdditionalProperties = marshalAnyFormatToJSONString(actor.AdditionalProperties)
	systemLog.ActorDetailEntry = marshalAnyFormatToJSONString(actor.DetailEntry)

	// AuthenticationContext info
	authContext := rawRow.GetAuthenticationContext()
	systemLog.AuthenticationProvider = authContext.AuthenticationProvider
	systemLog.AuthenticationStep = authContext.AuthenticationStep
	systemLog.CredentialProvider = authContext.CredentialProvider
	systemLog.CredentialType = authContext.CredentialType
	systemLog.ExternalSessionId = authContext.ExternalSessionId
	systemLog.Interface = authContext.Interface
	systemLog.Issuer = marshalAnyFormatToJSONString(authContext.Issuer)
	systemLog.ActorAdditionalProperties = marshalAnyFormatToJSONString(authContext.AdditionalProperties)

	// Client Info
	client := rawRow.GetClient()
	systemLog.ClientDevice = client.Device
	systemLog.ClientId = client.Id
	systemLog.ClientIpAddress = client.IpAddress
	systemLog.ClientZone = client.Zone
	systemLog.ClientGeographicalContext = marshalAnyFormatToJSONString(client.GeographicalContext)
	systemLog.ClientUserAgent = marshalAnyFormatToJSONString(client.UserAgent)
	systemLog.ClientAdditionalProperties = marshalAnyFormatToJSONString(client.AdditionalProperties)

	// LogDebugContext info
	debugContext := rawRow.GetDebugContext()
	systemLog.DebugData = marshalAnyFormatToJSONString(debugContext.DebugData)
	systemLog.DebugAdditionalProperties = marshalAnyFormatToJSONString(debugContext.AdditionalProperties)

	// Outcome Info
	outcome := rawRow.GetOutcome()
	systemLog.OutcomeReason = outcome.Reason
	systemLog.OutcomeResult = outcome.Result
	systemLog.OutcomeAdditionalProperties = marshalAnyFormatToJSONString(outcome.AdditionalProperties)

	// Request info
	request := rawRow.GetRequest()
	systemLog.IpChain = marshalAnyFormatToJSONString(request.IpChain)

	// SecurityContext info
	securityContext := rawRow.GetSecurityContext()
	systemLog.AsNumber = securityContext.AsNumber
	systemLog.AsOrg = securityContext.AsOrg
	systemLog.Domain = securityContext.Domain
	systemLog.Isp = securityContext.Isp
	systemLog.IsProxy = securityContext.IsProxy

	systemLog.Target = marshalAnyFormatToJSONString(rawRow.GetTarget())

	// Transaction info
	transaction := rawRow.GetTransaction()
	systemLog.TransactionId = transaction.Id
	systemLog.TransactionType = transaction.Type
	systemLog.TransactionDetail = marshalAnyFormatToJSONString(transaction.Detail)

	systemLog.AdditionalProperties = marshalAnyFormatToJSONString(rawRow.AdditionalProperties)

	return []*rows.SystemLog{systemLog}, nil
}

func marshalAnyFormatToJSONString(data any) *types.JSONString {
	if data == nil {
		return nil
	}
	s, err := json.Marshal(data)
	if err != nil {
		panic(fmt.Errorf("error marshalling row data: %w", err))
	}
	dataJsonString := types.JSONString(s)

	return &dataJsonString
}
