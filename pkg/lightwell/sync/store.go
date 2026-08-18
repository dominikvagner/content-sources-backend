package sync

import (
	"context"
	"errors"
	"fmt"

	dbstore "github.com/content-services/content-sources-backend/pkg/lightwell/db/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SaveOutcome int

const (
	SaveUnchanged SaveOutcome = iota
	SaveInserted
	SaveUpdated
)

type VulnerabilityStore interface {
	Find(ctx context.Context, vulnerabilityID string) (dbstore.LightwellVulnerability, error)
	Save(ctx context.Context, vulnerability Vulnerability, customerIDs []string, isNew bool) (SaveOutcome, error)
}

type SQLVulnerabilityStore struct {
	pool    *pgxpool.Pool
	queries *dbstore.Queries
}

func NewSQLVulnerabilityStore(pool *pgxpool.Pool) *SQLVulnerabilityStore {
	return &SQLVulnerabilityStore{pool: pool, queries: dbstore.New(pool)}
}

func (s *SQLVulnerabilityStore) Find(ctx context.Context, vulnerabilityID string) (dbstore.LightwellVulnerability, error) {
	return s.queries.GetVulnerabilityByID(ctx, vulnerabilityID)
}

func (s *SQLVulnerabilityStore) Save(
	ctx context.Context,
	vulnerability Vulnerability,
	customerIDs []string,
	isNew bool,
) (SaveOutcome, error) {
	if !isNew {
		outcome, _, err := upsert(ctx, s.queries, vulnerability)
		return outcome, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SaveUnchanged, fmt.Errorf("begin vulnerability transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	queries := s.queries.WithTx(tx)
	outcome, vulnerabilityUUID, err := upsert(ctx, queries, vulnerability)
	if err != nil {
		return SaveUnchanged, err
	}
	if outcome == SaveInserted {
		for _, customerID := range customerIDs {
			if err := queries.InsertVulnerabilityCustomer(ctx, dbstore.InsertVulnerabilityCustomerParams{
				CustomerID:        customerID,
				VulnerabilityUuid: vulnerabilityUUID,
			}); err != nil {
				return SaveUnchanged, fmt.Errorf("insert vulnerability customer: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return SaveUnchanged, fmt.Errorf("commit vulnerability transaction: %w", err)
	}
	return outcome, nil
}

func upsert(ctx context.Context, queries *dbstore.Queries, vulnerability Vulnerability) (SaveOutcome, uuid.UUID, error) {
	result, err := queries.UpsertVulnerability(ctx, dbstore.UpsertVulnerabilityParams{
		Uuid:               uuid.New(),
		VulnerabilityID:    vulnerability.VulnerabilityID,
		Purl:               vulnerability.PURL,
		ComponentName:      vulnerability.ComponentName,
		ComponentVersion:   vulnerability.ComponentVersion,
		Title:              vulnerability.Title,
		Cwe:                vulnerability.CWE,
		Description:        vulnerability.Description,
		Severity:           vulnerability.Severity,
		Cvss:               vulnerability.CVSS,
		CvssVector:         vulnerability.CVSSVector,
		ExploitTested:      vulnerability.ExploitTested,
		ReproducerIncluded: vulnerability.ReproducerIncluded,
		CustomerPriority:   vulnerability.CustomerPriority,
		Stage:              vulnerability.Stage,
		Language:           vulnerability.Language,
		Complexity:         vulnerability.Complexity,
		SubmittedDate:      vulnerability.SubmittedDate,
		LastUpdated:        vulnerability.LastUpdated,
		Embargo:            vulnerability.Embargo,
		Duplicate:          vulnerability.Duplicate,
		LtwwlsuptTicketID:  vulnerability.LtwwlsuptTicketID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SaveUnchanged, uuid.UUID{}, nil
	}
	if err != nil {
		return SaveUnchanged, uuid.UUID{}, fmt.Errorf("upsert vulnerability: %w", err)
	}
	if result.Inserted {
		return SaveInserted, result.Uuid, nil
	}
	return SaveUpdated, result.Uuid, nil
}
