package mappers

import (
	"context"
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
	systemLog.Actor = &rows.OktaSystemLogActor{
		AlternateId: actor.AlternateId,
		DetailEntry: actor.DetailEntry,
	}

	// AuthenticationContext info
	authenticationContext := rawRow.GetAuthenticationContext()
	systemLog.AuthenticationContext = &rows.OktaSystemLogAuthenticationContext{
		AuthenticationProvider: authenticationContext.AuthenticationProvider,
		AuthenticationStep:     authenticationContext.AuthenticationStep,
		CredentialProvider:     authenticationContext.CredentialProvider,
		CredentialType:         authenticationContext.CredentialType,
		ExternalSessionId:      authenticationContext.ExternalSessionId,
		Interface:              authenticationContext.Interface,
		AdditionalProperties:   authenticationContext.AdditionalProperties,
	}

	if authenticationContext.Issuer != nil {
		systemLog.AuthenticationContext.Issuer = &rows.LogIssuer{
			Id:                   authenticationContext.Issuer.Id,
			Type:                 authenticationContext.Issuer.Type,
			AdditionalProperties: authenticationContext.Issuer.AdditionalProperties,
		}
	}

	// Client Info
	client := rawRow.GetClient()
	systemLog.Client = &rows.OktaSystemLogClient{
		Device:               client.Device,
		Id:                   client.Id,
		IpAddress:            client.IpAddress,
		Zone:                 client.Zone,
		AdditionalProperties: client.AdditionalProperties,
	}
	if client.GeographicalContext != nil {
		systemLog.Client.GeographicalContext = &rows.LogGeographicalContext{
			City:                 client.GeographicalContext.City,
			Country:              client.GeographicalContext.Country,
			Geolocation:          (*rows.LogGeolocation)(client.GeographicalContext.Geolocation),
			PostalCode:           client.GeographicalContext.PostalCode,
			State:                client.GetGeographicalContext().State,
			AdditionalProperties: client.GeographicalContext.AdditionalProperties,
		}
	}

	if client.UserAgent != nil {
		systemLog.Client.UserAgent = &rows.LogUserAgent{
			Browser:              client.UserAgent.Browser,
			Os:                   client.UserAgent.Os,
			RawUserAgent:         client.UserAgent.RawUserAgent,
			AdditionalProperties: client.UserAgent.AdditionalProperties,
		}
	}

	// LogDebugContext info
	debugContext := rawRow.GetDebugContext()
	systemLog.DebugContext = &rows.OktaSystemLogDebugContext{
		DebugData:            debugContext.DebugData,
		AdditionalProperties: debugContext.AdditionalProperties,
	}

	// Outcome Info
	outcome := rawRow.GetOutcome()
	systemLog.Outcome = &rows.OktaSystemLogOutcome{
		Reason:               outcome.Reason,
		Result:               outcome.Result,
		AdditionalProperties: outcome.AdditionalProperties,
	}

	// Request info
	req := rawRow.GetRequest()
	systemLog.Request = &rows.OktaSystemLogRequest{
		IpChain:              req.IpChain,
		AdditionalProperties: req.AdditionalProperties,
	}

	// SecurityContext info
	securityContext := rawRow.GetSecurityContext()
	systemLog.SecurityContext = &rows.OktaSystemLogSecurityContext{
		AsNumber:             securityContext.AsNumber,
		AsOrg:                securityContext.AsOrg,
		Domain:               securityContext.Domain,
		Isp:                  securityContext.Isp,
		IsProxy:              securityContext.IsProxy,
		AdditionalProperties: securityContext.AdditionalProperties,
	}

	// Target info
	systemLog.Target = rawRow.GetTarget()

	// Transaction info
	transaction := rawRow.GetTransaction()
	systemLog.Transaction = &rows.OktaSystemLogTransaction{
		Detail:               transaction.Detail,
		Id:                   transaction.Id,
		Type:                 transaction.Type,
		AdditionalProperties: transaction.AdditionalProperties,
	}

	systemLog.AdditionalProperties = &rawRow.AdditionalProperties

	return systemLog, nil
}
