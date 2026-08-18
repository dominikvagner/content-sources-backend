package jobs

import (
	"context"
	"fmt"

	"github.com/content-services/content-sources-backend/pkg/config"
	"github.com/content-services/content-sources-backend/pkg/db"
	lightwellsync "github.com/content-services/content-sources-backend/pkg/lightwell/sync"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

func SyncLightwellVulnerabilities(_ []string) {
	summary, err := runLightwellVulnerabilitySync(context.Background())
	logEvent := log.Info()
	if err != nil {
		logEvent = log.Error().Err(err)
	}
	logEvent.
		Int("inserted", summary.Inserted).
		Int("updated", summary.Updated).
		Int("unchanged", summary.Unchanged).
		Int("failed", summary.Failed).
		Msg("Finished syncing Lightwell vulnerabilities from Jira")
	if err != nil {
		log.Fatal().Err(err).Msg("Lightwell vulnerability sync failed")
	}
}

func runLightwellVulnerabilitySync(ctx context.Context) (lightwellsync.SyncSummary, error) {
	jiraConfig := config.Get().Clients.Jira
	jiraClient, err := lightwellsync.NewAtlassianJiraClient(jiraConfig.URL, jiraConfig.User, jiraConfig.Token)
	if err != nil {
		return lightwellsync.SyncSummary{}, err
	}

	pool, err := pgxpool.New(ctx, db.GetUrl())
	if err != nil {
		return lightwellsync.SyncSummary{}, fmt.Errorf("create Lightwell database pool: %w", err)
	}
	defer pool.Close()

	ingestor := lightwellsync.NewIngestor(jiraClient, lightwellsync.NewSQLVulnerabilityStore(pool))
	return ingestor.Sync(ctx)
}
