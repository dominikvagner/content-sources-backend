package sync

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

const VulnerabilityJQL = "project = LTWL AND type = Vulnerability ORDER BY created ASC"

var vulnerabilityFields = []string{
	"description",
	"status",
	"created",
	"updated",
	"labels",
	"issuelinks",
	fieldPURL,
	fieldCWE,
	fieldSeverity,
	fieldCVSS,
	fieldEmbargo,
}

type SyncSummary struct {
	Inserted  int
	Updated   int
	Unchanged int
	Failed    int
}

type Ingestor struct {
	jira  JiraClient
	store VulnerabilityStore
	cache map[string]cachedIssue
}

type cachedIssue struct {
	issue JiraIssue
	err   error
}

func NewIngestor(jira JiraClient, store VulnerabilityStore) *Ingestor {
	return &Ingestor{jira: jira, store: store, cache: make(map[string]cachedIssue)}
}

func (i *Ingestor) Sync(ctx context.Context) (SyncSummary, error) {
	accountFieldID, err := i.accountFieldID(ctx)
	if err != nil {
		return SyncSummary{}, err
	}

	issues, err := i.searchAll(ctx)
	if err != nil {
		return SyncSummary{}, err
	}

	var summary SyncSummary
	issueErrors := make([]error, 0)
	for _, issue := range issues {
		if err := i.syncIssue(ctx, issue, accountFieldID, &summary); err != nil {
			summary.Failed++
			issueErrors = append(issueErrors, err)
		}
	}
	return summary, errors.Join(issueErrors...)
}

func (i *Ingestor) searchAll(ctx context.Context) ([]JiraIssue, error) {
	issues := make([]JiraIssue, 0)
	nextPageToken := ""
	seenTokens := make(map[string]struct{})
	for {
		page, err := i.jira.Search(ctx, VulnerabilityJQL, vulnerabilityFields, nextPageToken)
		if err != nil {
			return nil, err
		}
		issues = append(issues, page.Issues...)
		if page.NextPageToken == "" {
			return issues, nil
		}
		if _, seen := seenTokens[page.NextPageToken]; seen {
			return nil, fmt.Errorf("Jira repeated pagination token %q", page.NextPageToken)
		}
		seenTokens[page.NextPageToken] = struct{}{}
		nextPageToken = page.NextPageToken
	}
}

func (i *Ingestor) accountFieldID(ctx context.Context) (string, error) {
	fields, err := i.jira.Fields(ctx)
	if err != nil {
		return "", err
	}
	matches := make([]string, 0, 1)
	for _, field := range fields {
		if strings.EqualFold(strings.TrimSpace(field.Name), "Account Number") {
			matches = append(matches, field.ID)
		}
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("multiple Jira fields named Account Number: %s", strings.Join(matches, ", "))
	}
	if len(matches) == 0 {
		return "", nil
	}
	return matches[0], nil
}

func (i *Ingestor) syncIssue(ctx context.Context, issue JiraIssue, accountFieldID string, summary *SyncSummary) error {
	vulnerability, err := mapVulnerability(issue)
	if err != nil {
		return err
	}

	existing, err := i.store.Find(ctx, vulnerability.VulnerabilityID)
	isNew := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !isNew {
		return fmt.Errorf("issue %s database lookup: %w", issue.Key, err)
	}

	var customerIDs []string
	if isNew {
		vulnerability.LtwwlsuptTicketID, customerIDs, err = i.newIssueRelationships(ctx, issue, accountFieldID)
		if err != nil {
			return fmt.Errorf("issue %s relationships: %w", issue.Key, err)
		}
	} else {
		vulnerability.LtwwlsuptTicketID = existing.LtwwlsuptTicketID
	}

	outcome, err := i.store.Save(ctx, vulnerability, customerIDs, isNew)
	if err != nil {
		return fmt.Errorf("issue %s database save: %w", issue.Key, err)
	}
	switch outcome {
	case SaveInserted:
		summary.Inserted++
	case SaveUpdated:
		summary.Updated++
	default:
		summary.Unchanged++
	}
	return nil
}

func (i *Ingestor) newIssueRelationships(ctx context.Context, vulnerability JiraIssue, accountFieldID string) (string, []string, error) {
	batchKey := linkedIssueKey(vulnerability, "relates to")
	if batchKey == "" {
		return "", nil, nil
	}
	batch, err := i.issue(ctx, batchKey, []string{"parent", "issuelinks"})
	if err != nil {
		return "", nil, err
	}

	epicKey := parentIssueKey(batch)
	if epicKey == "" {
		epicKey = linkedIssueKey(batch, "is child of")
	}
	if epicKey == "" || accountFieldID == "" {
		return epicKey, nil, nil
	}
	epic, err := i.issue(ctx, epicKey, []string{accountFieldID})
	if err != nil {
		return "", nil, err
	}
	return epicKey, normalizedValues(epic.Fields[accountFieldID]), nil
}

func (i *Ingestor) issue(ctx context.Context, key string, fields []string) (JiraIssue, error) {
	if cached, exists := i.cache[key]; exists {
		return cached.issue, cached.err
	}
	issue, err := i.jira.Issue(ctx, key, fields)
	i.cache[key] = cachedIssue{issue: issue, err: err}
	return issue, err
}
