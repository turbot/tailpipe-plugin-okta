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

	systemLog.Issuer = &rows.OktaAuthContextIssuer{}

	if authContext.Issuer != nil && authContext.Issuer.Id != nil {
		systemLog.Issuer = &rows.OktaAuthContextIssuer{
			Id:                   authContext.Issuer.Id,
			Type:                 authContext.Issuer.Type,
			AdditionalProperties: &authContext.Issuer.AdditionalProperties,
		}
	}

	systemLog.ActorAdditionalProperties = &authContext.AdditionalProperties

	// Client Info
	client := rawRow.GetClient()
	systemLog.ClientDevice = client.Device
	systemLog.ClientId = client.Id
	systemLog.ClientIpAddress = client.IpAddress
	systemLog.ClientZone = client.Zone

	if client.GeographicalContext != nil {
		systemLog.ClientGeographicalContext = rows.OktaLogClient{
			Device:               systemLog.ClientGeographicalContext.Device,
			Id:                   systemLog.ClientGeographicalContext.Id,
			IpAddress:            systemLog.ClientGeographicalContext.IpAddress,
			Zone:                 systemLog.ClientGeographicalContext.Zone,
			GeographicalContext:  systemLog.ClientGeographicalContext.GeographicalContext,
			UserAgent:            systemLog.ClientGeographicalContext.UserAgent,
			AdditionalProperties: systemLog.ClientGeographicalContext.AdditionalProperties,
		}
	}

	if client.UserAgent != nil {
		systemLog.ClientUserAgent = rows.OktaUserAgent{
			Browser:              client.UserAgent.Browser,
			Os:                   client.UserAgent.Os,
			RawUserAgent:         client.UserAgent.RawUserAgent,
			AdditionalProperties: client.UserAgent.AdditionalProperties,
		}
	}

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

	var ipChains []rows.LogIpAddress
	if request.IpChain != nil {
		for _, chain := range request.IpChain {
			ipChain := rows.LogIpAddress{}
			ipChain.Ip = chain.Ip
			ipChain.Source = chain.Source
			ipChain.GeographicalContext = &rows.OktaLogGeographicalContext{
				City:                 chain.GeographicalContext.City,
				Country:              chain.GeographicalContext.Country,
				Geolocation:          (*rows.LogGeolocation)(chain.GeographicalContext.Geolocation),
				PostalCode:           chain.GeographicalContext.PostalCode,
				AdditionalProperties: chain.GeographicalContext.AdditionalProperties,
			}
			ipChain.Version = chain.Version
			ipChains = append(ipChains, ipChain)
		}
	}

	systemLog.IpChain = rows.OktaIpChain{
		IpChain: ipChains,
	}

	// SecurityContext info
	securityContext := rawRow.GetSecurityContext()
	systemLog.AsNumber = securityContext.AsNumber
	systemLog.AsOrg = securityContext.AsOrg
	systemLog.Domain = securityContext.Domain
	systemLog.Isp = securityContext.Isp
	systemLog.IsProxy = securityContext.IsProxy

	// Target info
	var targets []rows.OktaLogTarget
	for _, target := range rawRow.GetTarget() {
		logTarget := rows.OktaLogTarget{}
		logTarget.AlternateId = target.AlternateId
		logTarget.DisplayName = target.DisplayName
		logTarget.Id = target.Id
		logTarget.Type = target.Type
		logTarget.AdditionalProperties = target.AdditionalProperties
		logTarget.DetailEntry = target.DetailEntry
		if target.ChangeDetails != nil {
			logTarget.ChangeDetails = &rows.LogTargetChangeDetails{
				From:                 target.ChangeDetails.From,
				To:                   target.ChangeDetails.To,
				AdditionalProperties: target.ChangeDetails.AdditionalProperties,
			}
		}
		targets = append(targets, logTarget)
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
