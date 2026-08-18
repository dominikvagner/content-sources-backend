package sync

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	dbstore "github.com/content-services/content-sources-backend/pkg/lightwell/db/store"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeJira struct {
	fields      []JiraField
	fieldErr    error
	pages       map[string]JiraPage
	searchErr   error
	issues      map[string]JiraIssue
	issueCalls  []string
	issueFields [][]string
	searchCalls []string
}

func (f *fakeJira) Fields(context.Context) ([]JiraField, error) {
	return f.fields, f.fieldErr
}

func (f *fakeJira) Search(_ context.Context, _ string, _ []string, token string) (JiraPage, error) {
	f.searchCalls = append(f.searchCalls, token)
	if f.searchErr != nil {
		return JiraPage{}, f.searchErr
	}
	return f.pages[token], nil
}

func (f *fakeJira) Issue(_ context.Context, key string, fields []string) (JiraIssue, error) {
	f.issueCalls = append(f.issueCalls, key)
	f.issueFields = append(f.issueFields, fields)
	issue, exists := f.issues[key]
	if !exists {
		return JiraIssue{}, errors.New("missing fake issue")
	}
	return issue, nil
}

type savedVulnerability struct {
	vulnerability Vulnerability
	customers     []string
	isNew         bool
}

type fakeVulnerabilityStore struct {
	existing map[string]dbstore.LightwellVulnerability
	saved    []savedVulnerability
	outcome  SaveOutcome
}

func (f *fakeVulnerabilityStore) Find(_ context.Context, id string) (dbstore.LightwellVulnerability, error) {
	if existing, found := f.existing[id]; found {
		return existing, nil
	}
	return dbstore.LightwellVulnerability{}, pgx.ErrNoRows
}

func (f *fakeVulnerabilityStore) Save(_ context.Context, vulnerability Vulnerability, customers []string, isNew bool) (SaveOutcome, error) {
	f.saved = append(f.saved, savedVulnerability{vulnerability: vulnerability, customers: customers, isNew: isNew})
	return f.outcome, nil
}

func TestIngestorSyncPaginatesAndLoadsNewRelationships(t *testing.T) {
	vulnerability := validJiraIssue("LTWL-1")
	vulnerability.Fields["issuelinks"] = json.RawMessage(`[{
		"type":{"outward":"relates to"},"outwardIssue":{"key":"BATCH-1"}
	}]`)
	batch := JiraIssue{Key: "BATCH-1", Fields: map[string]json.RawMessage{
		"issuelinks": json.RawMessage(`[{
			"type":{"outward":"is child of"},"outwardIssue":{"key":"EPIC-1"}
		}]`),
	}}
	epic := JiraIssue{Key: "EPIC-1", Fields: map[string]json.RawMessage{
		"customfield_account": json.RawMessage(`["123",{"value":"456"},"123"]`),
	}}

	jira := &fakeJira{
		fields: []JiraField{{ID: "customfield_account", Name: "Account Number"}},
		pages: map[string]JiraPage{
			"":     {NextPageToken: "next"},
			"next": {Issues: []JiraIssue{vulnerability}},
		},
		issues: map[string]JiraIssue{"BATCH-1": batch, "EPIC-1": epic},
	}
	store := &fakeVulnerabilityStore{outcome: SaveInserted}

	summary, err := NewIngestor(jira, store).Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, SyncSummary{Inserted: 1}, summary)
	require.Len(t, store.saved, 1)
	assert.True(t, store.saved[0].isNew)
	assert.Equal(t, "EPIC-1", store.saved[0].vulnerability.LtwwlsuptTicketID)
	assert.Equal(t, []string{"123", "456"}, store.saved[0].customers)
	assert.Equal(t, []string{"", "next"}, jira.searchCalls)
	assert.Equal(t, []string{"BATCH-1", "EPIC-1"}, jira.issueCalls)
}

func TestIngestorExistingIssueDoesNotLoadRelationships(t *testing.T) {
	issue := validJiraIssue("LTWL-1")
	issue.Fields["issuelinks"] = json.RawMessage(`[{"type":{"outward":"relates to"},"outwardIssue":{"key":"BATCH-1"}}]`)
	jira := &fakeJira{pages: map[string]JiraPage{"": {Issues: []JiraIssue{issue}}}}
	store := &fakeVulnerabilityStore{
		existing: map[string]dbstore.LightwellVulnerability{
			"LTWL-1": {VulnerabilityID: "LTWL-1", LtwwlsuptTicketID: "EPIC-OLD"},
		},
		outcome: SaveUnchanged,
	}

	summary, err := NewIngestor(jira, store).Sync(context.Background())
	require.NoError(t, err)
	assert.Equal(t, SyncSummary{Unchanged: 1}, summary)
	assert.Empty(t, jira.issueCalls)
	require.Len(t, store.saved, 1)
	assert.False(t, store.saved[0].isNew)
	assert.Equal(t, "EPIC-OLD", store.saved[0].vulnerability.LtwwlsuptTicketID)
}

func TestIngestorStoresEpicFromBatchParent(t *testing.T) {
	vulnerability := validJiraIssue("LTWL-1")
	vulnerability.Fields["issuelinks"] = json.RawMessage(`[{ 
		"type":{"outward":"relates to"},"outwardIssue":{"key":"BATCH-1"}
	}]`)
	batch := JiraIssue{Key: "BATCH-1", Fields: map[string]json.RawMessage{
		"parent": json.RawMessage(`{"key":"EPIC-1"}`),
	}}
	jira := &fakeJira{
		pages:  map[string]JiraPage{"": {Issues: []JiraIssue{vulnerability}}},
		issues: map[string]JiraIssue{"BATCH-1": batch},
	}
	store := &fakeVulnerabilityStore{outcome: SaveInserted}

	_, err := NewIngestor(jira, store).Sync(context.Background())
	require.NoError(t, err)
	require.Len(t, store.saved, 1)
	assert.Equal(t, []string{"parent", "issuelinks"}, jira.issueFields[0])
	assert.Equal(t, "EPIC-1", store.saved[0].vulnerability.LtwwlsuptTicketID)
}

func TestIngestorContinuesAfterIssueMappingFailure(t *testing.T) {
	bad := validJiraIssue("LTWL-BAD")
	delete(bad.Fields, "created")
	good := validJiraIssue("LTWL-GOOD")
	jira := &fakeJira{pages: map[string]JiraPage{"": {Issues: []JiraIssue{bad, good}}}}
	store := &fakeVulnerabilityStore{outcome: SaveInserted}

	summary, err := NewIngestor(jira, store).Sync(context.Background())
	assert.Error(t, err)
	assert.Equal(t, SyncSummary{Inserted: 1, Failed: 1}, summary)
	assert.Len(t, store.saved, 1)
}

func TestIngestorSearchFailureWritesNothing(t *testing.T) {
	jira := &fakeJira{searchErr: errors.New("search failed")}
	store := &fakeVulnerabilityStore{outcome: SaveInserted}

	_, err := NewIngestor(jira, store).Sync(context.Background())
	assert.ErrorContains(t, err, "search failed")
	assert.Empty(t, store.saved)
}

func TestIngestorRejectsAmbiguousAccountField(t *testing.T) {
	jira := &fakeJira{fields: []JiraField{
		{ID: "customfield_1", Name: "Account Number"},
		{ID: "customfield_2", Name: "account number"},
	}}

	_, err := NewIngestor(jira, &fakeVulnerabilityStore{}).Sync(context.Background())
	assert.ErrorContains(t, err, "multiple Jira fields")
}
