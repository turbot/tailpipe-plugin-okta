package sources

import (
	"context"
	"fmt"

	"github.com/okta/okta-sdk-golang/v5/okta"
	"github.com/turbot/tailpipe-plugin-okta/config"
	"github.com/turbot/tailpipe-plugin-sdk/collection_state"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/schema"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

const SystemLogAPISourceIdentifier = "okta_system_log_api"

// register the source from the package init function
func init() {
	row_source.RegisterRowSource[*SystemLogAPISource]()
}

// SystemLogAPISource source is responsible for collecting audit logs from Turbot Okta API
type SystemLogAPISource struct {
	row_source.RowSourceImpl[*SystemLogAPISourceConfig, *config.OktaConnection]
}

func (s *SystemLogAPISource) Init(ctx context.Context, configData types.ConfigData, connectionData types.ConfigData, opts ...row_source.RowSourceOption) error {
	// set the collection state ctor
	s.NewCollectionStateFunc = collection_state.NewTimeRangeCollectionState

	// call base init
	return s.RowSourceImpl.Init(ctx, configData, connectionData, opts...)
}

func (s *SystemLogAPISource) Identifier() string {
	return SystemLogAPISourceIdentifier
}

func (s *SystemLogAPISource) Collect(ctx context.Context) error {
	// NOTE: The API only allows fetching from newest to oldest, so we need to collect in reverse order until we've hit a previously obtained item.
	collectionState := s.CollectionState.(*collection_state.TimeRangeCollectionState[*SystemLogAPISourceConfig])
	collectionState.IsChronological = false
	collectionState.HasContinuation = false
	collectionState.StartCollection()

	// Initialize variable with default value
	var requestTimeout, maxBackoff int64 = 60, 30
	var maxRetries int32 = 5

	if s.Config.MaxBackoff != nil && *s.Config.MaxBackoff > 0 {
		maxBackoff = *s.Config.MaxBackoff
	}

	if s.Config.MaxRetries != nil && *s.Config.MaxRetries > 0 {
		maxRetries = *s.Config.MaxRetries
	}

	if s.Config.RequestTimeout != nil && *s.Config.RequestTimeout > 0 {
		requestTimeout = *s.Config.RequestTimeout
	}

	// Create a default configuration
	configuration, err := okta.NewConfiguration(
		okta.WithOrgUrl(*s.Connection.Domain),
		okta.WithToken(*s.Connection.Token),
		okta.WithRateLimitMaxBackOff(maxBackoff),
		okta.WithRateLimitMaxRetries(maxRetries),
		okta.WithRequestTimeout(requestTimeout),
		okta.WithScopes([]string{"okta.logs.read"}),
	)

	if err != nil {
		return fmt.Errorf("error in creating okta client configuration: %w", err)
	}

	// Create a client
	client := okta.NewAPIClient(configuration)

	// populate enrichment fields the source is aware of
	// - in this case the connection
	tpSource := fmt.Sprint(SystemLogAPISourceIdentifier)
	sourceEnrichmentFields := &schema.SourceEnrichment{
		CommonFields: schema.CommonFields{
			TpSourceName:     &tpSource,
			TpSourceType:     SystemLogAPISourceIdentifier,
			TpSourceLocation: s.Connection.Domain,
		},
	}

	// Limiting the results to 500 per page.
	// Increasing the limit beyond this can result in a "context deadline exceeded" error.
	// The supported limit range is between 0 and 1000.
	result, resp, err := client.SystemLogAPI.ListLogEvents(ctx).Limit(500).SortOrder("DESCENDING").Execute()
	if err != nil {
		return fmt.Errorf("error in getting okta system logs: %w", err)
	}

	var allSystemLogs []okta.LogEvent

	allSystemLogs = append(allSystemLogs, result...)

	// Checks we have items, and that we have not processed all items previously
	for resp.HasNextPage() {

		var nextSystemLogs []okta.LogEvent

		resp, err = resp.Next(&nextSystemLogs)
		if err != nil {
			return fmt.Errorf("error in paging okta system logs: %w", err)
		}

		allSystemLogs = append(allSystemLogs, nextSystemLogs...)

		// The API often returns "resp.HasNextPage()" as true, even when there are no more results on the next page.
		// To prevent unnecessary requests, we check the number of results in the current page.
		// If the result count is less than the specified limit (500), it indicates there are no more pages, so we break the loop.
		if len(nextSystemLogs) < 500 {
			break
		}
	}

	for _, item := range allSystemLogs {
		// check if we've hit previous item - end collection and return if we have
		// TODO: #collectionState this will fill until we hit record in previous state, but what if we have gaps? [incoming data] -> [data]ENDS-HERE -> [gap] -> [data]
		if !collectionState.ShouldCollectRow(*item.Published, item.GetUuid()) {
			collectionState.EndCollection()
			return nil
		}

		// populate artifact data
		row := &types.RowData{Data: item, SourceEnrichment: sourceEnrichmentFields}

		// update collection state
		collectionState.Upsert(*item.Published, *item.Uuid, nil)
		collectionStateJSON, err := s.GetCollectionStateJSON()
		if err != nil {
			return fmt.Errorf("error serialising collectionState data: %w", err)
		}

		if err := s.OnRow(ctx, row, collectionStateJSON); err != nil {
			return fmt.Errorf("error processing row: %w", err)
		}
	}

	collectionState.EndCollection()
	return nil
}
