-- name: ListCustomerIds :many
SELECT DISTINCT customer_id
FROM lightwell_vulnerability_customers
ORDER BY customer_id;

-- name: GetVulnerabilityByID :one
SELECT *
FROM lightwell_vulnerabilities
WHERE vulnerability_id = sqlc.arg(vulnerability_id);

-- name: UpsertVulnerability :one
INSERT INTO lightwell_vulnerabilities (
    uuid, vulnerability_id, purl, component_name, component_version, title, cwe, description,
    severity, cvss, cvss_vector, exploit_tested, reproducer_included, customer_priority, stage,
    language, complexity, submitted_date, last_updated, embargo, duplicate, ltwwlsupt_ticket_id
) VALUES (
    sqlc.arg(uuid), sqlc.arg(vulnerability_id), sqlc.narg(purl), sqlc.arg(component_name),
    sqlc.arg(component_version), sqlc.narg(title), sqlc.narg(cwe), sqlc.narg(description),
    sqlc.arg(severity), sqlc.narg(cvss), sqlc.narg(cvss_vector), sqlc.arg(exploit_tested),
    sqlc.arg(reproducer_included), sqlc.narg(customer_priority), sqlc.arg(stage),
    sqlc.narg(language), sqlc.arg(complexity), sqlc.arg(submitted_date), sqlc.arg(last_updated),
    sqlc.arg(embargo), sqlc.arg(duplicate), sqlc.arg(ltwwlsupt_ticket_id)
)
ON CONFLICT (vulnerability_id) DO UPDATE SET
    purl = EXCLUDED.purl,
    component_name = EXCLUDED.component_name,
    component_version = EXCLUDED.component_version,
    title = EXCLUDED.title,
    cwe = EXCLUDED.cwe,
    description = EXCLUDED.description,
    severity = EXCLUDED.severity,
    cvss = EXCLUDED.cvss,
    cvss_vector = EXCLUDED.cvss_vector,
    exploit_tested = EXCLUDED.exploit_tested,
    reproducer_included = EXCLUDED.reproducer_included,
    customer_priority = EXCLUDED.customer_priority,
    stage = EXCLUDED.stage,
    language = EXCLUDED.language,
    complexity = EXCLUDED.complexity,
    submitted_date = EXCLUDED.submitted_date,
    last_updated = EXCLUDED.last_updated,
    embargo = EXCLUDED.embargo,
    duplicate = EXCLUDED.duplicate,
    ltwwlsupt_ticket_id = EXCLUDED.ltwwlsupt_ticket_id,
    updated_at = NOW()
WHERE (
    lightwell_vulnerabilities.purl, lightwell_vulnerabilities.component_name,
    lightwell_vulnerabilities.component_version, lightwell_vulnerabilities.title,
    lightwell_vulnerabilities.cwe, lightwell_vulnerabilities.description,
    lightwell_vulnerabilities.severity, lightwell_vulnerabilities.cvss,
    lightwell_vulnerabilities.cvss_vector, lightwell_vulnerabilities.exploit_tested,
    lightwell_vulnerabilities.reproducer_included, lightwell_vulnerabilities.customer_priority,
    lightwell_vulnerabilities.stage, lightwell_vulnerabilities.language,
    lightwell_vulnerabilities.complexity, lightwell_vulnerabilities.submitted_date,
    lightwell_vulnerabilities.last_updated, lightwell_vulnerabilities.embargo,
    lightwell_vulnerabilities.duplicate, lightwell_vulnerabilities.ltwwlsupt_ticket_id
) IS DISTINCT FROM (
    EXCLUDED.purl, EXCLUDED.component_name, EXCLUDED.component_version, EXCLUDED.title,
    EXCLUDED.cwe, EXCLUDED.description, EXCLUDED.severity, EXCLUDED.cvss,
    EXCLUDED.cvss_vector, EXCLUDED.exploit_tested, EXCLUDED.reproducer_included,
    EXCLUDED.customer_priority, EXCLUDED.stage, EXCLUDED.language, EXCLUDED.complexity,
    EXCLUDED.submitted_date, EXCLUDED.last_updated, EXCLUDED.embargo, EXCLUDED.duplicate,
    EXCLUDED.ltwwlsupt_ticket_id
)
RETURNING uuid, (xmax = 0) AS inserted;

-- name: InsertVulnerabilityCustomer :exec
INSERT INTO lightwell_vulnerability_customers (customer_id, vulnerability_uuid)
VALUES (sqlc.arg(customer_id), sqlc.arg(vulnerability_uuid))
ON CONFLICT DO NOTHING;

-- name: ListVulnerabilities :many
SELECT
    v.uuid,
    v.vulnerability_id,
    v.purl,
    v.component_name,
    v.component_version,
    v.title,
    v.cwe,
    v.description,
    v.severity,
    v.cvss,
    v.cvss_vector,
    v.exploit_tested,
    v.reproducer_included,
    v.customer_priority,
    v.stage,
    v.language,
    v.complexity,
    v.submitted_date,
    v.last_updated,
    v.embargo,
    v.duplicate,
    v.ltwwlsupt_ticket_id,
    v.created_at,
    v.updated_at
FROM lightwell_vulnerabilities v
INNER JOIN lightwell_vulnerability_customers vc ON vc.vulnerability_uuid = v.uuid
WHERE vc.customer_id = sqlc.arg(customer_id)
    AND (
        sqlc.narg(severities)::text[] IS NULL
        OR cardinality(sqlc.narg(severities)::text[]) = 0
        OR v.severity = ANY (sqlc.narg(severities)::text[])
    )
    AND (
        sqlc.narg(stages)::text[] IS NULL
        OR cardinality(sqlc.narg(stages)::text[]) = 0
        OR v.stage = ANY (sqlc.narg(stages)::text[])
    )
    AND (
        sqlc.narg(complexities)::text[] IS NULL
        OR cardinality(sqlc.narg(complexities)::text[]) = 0
        OR v.complexity = ANY (sqlc.narg(complexities)::text[])
    )
    AND (
        sqlc.narg(ltwwlsupt_ticket_ids)::text[] IS NULL
        OR cardinality(sqlc.narg(ltwwlsupt_ticket_ids)::text[]) = 0
        OR v.ltwwlsupt_ticket_id = ANY (sqlc.narg(ltwwlsupt_ticket_ids)::text[])
    )
    AND (
        sqlc.narg(flag)::text IS NULL
        OR (
            sqlc.narg(flag)::text = 'embargo'
            AND v.embargo = true
        )
        OR (
            sqlc.narg(flag)::text = 'duplicate'
            AND v.duplicate = true
        )
    )
    AND (
        sqlc.narg(search)::text IS NULL
        OR v.vulnerability_id ILIKE '%' || sqlc.narg(search) || '%'
        OR v.component_name ILIKE '%' || sqlc.narg(search) || '%'
        OR v.title ILIKE '%' || sqlc.narg(search) || '%'
    )
ORDER BY v.last_updated DESC, v.vulnerability_id ASC
LIMIT sqlc.arg(page_limit) OFFSET sqlc.arg(page_offset);

-- name: CountAggregates :one
SELECT
    COUNT(*)::bigint AS total_count,
    COUNT(*) FILTER (WHERE v.severity = 'Critical')::bigint AS critical_count,
    COUNT(*) FILTER (WHERE v.embargo = true)::bigint AS embargo_count,
    COUNT(*) FILTER (
        WHERE v.stage <> 'Lightwell Network'
            AND (CURRENT_DATE - v.submitted_date) > 30
    )::bigint AS blocked_count
FROM lightwell_vulnerabilities v
INNER JOIN lightwell_vulnerability_customers vc ON vc.vulnerability_uuid = v.uuid
WHERE vc.customer_id = sqlc.arg(customer_id)
    AND (
        sqlc.narg(severities)::text[] IS NULL
        OR cardinality(sqlc.narg(severities)::text[]) = 0
        OR v.severity = ANY (sqlc.narg(severities)::text[])
    )
    AND (
        sqlc.narg(stages)::text[] IS NULL
        OR cardinality(sqlc.narg(stages)::text[]) = 0
        OR v.stage = ANY (sqlc.narg(stages)::text[])
    )
    AND (
        sqlc.narg(complexities)::text[] IS NULL
        OR cardinality(sqlc.narg(complexities)::text[]) = 0
        OR v.complexity = ANY (sqlc.narg(complexities)::text[])
    )
    AND (
        sqlc.narg(ltwwlsupt_ticket_ids)::text[] IS NULL
        OR cardinality(sqlc.narg(ltwwlsupt_ticket_ids)::text[]) = 0
        OR v.ltwwlsupt_ticket_id = ANY (sqlc.narg(ltwwlsupt_ticket_ids)::text[])
    )
    AND (
        sqlc.narg(flag)::text IS NULL
        OR (
            sqlc.narg(flag)::text = 'embargo'
            AND v.embargo = true
        )
        OR (
            sqlc.narg(flag)::text = 'duplicate'
            AND v.duplicate = true
        )
    )
    AND (
        sqlc.narg(search)::text IS NULL
        OR v.vulnerability_id ILIKE '%' || sqlc.narg(search) || '%'
        OR v.component_name ILIKE '%' || sqlc.narg(search) || '%'
        OR v.title ILIKE '%' || sqlc.narg(search) || '%'
    );

-- name: CountByStage :many
SELECT
    v.stage,
    COUNT(*)::bigint AS count
FROM lightwell_vulnerabilities v
INNER JOIN lightwell_vulnerability_customers vc ON vc.vulnerability_uuid = v.uuid
WHERE vc.customer_id = sqlc.arg(customer_id)
    AND (
        sqlc.narg(severities)::text[] IS NULL
        OR cardinality(sqlc.narg(severities)::text[]) = 0
        OR v.severity = ANY (sqlc.narg(severities)::text[])
    )
    AND (
        sqlc.narg(stages)::text[] IS NULL
        OR cardinality(sqlc.narg(stages)::text[]) = 0
        OR v.stage = ANY (sqlc.narg(stages)::text[])
    )
    AND (
        sqlc.narg(complexities)::text[] IS NULL
        OR cardinality(sqlc.narg(complexities)::text[]) = 0
        OR v.complexity = ANY (sqlc.narg(complexities)::text[])
    )
    AND (
        sqlc.narg(ltwwlsupt_ticket_ids)::text[] IS NULL
        OR cardinality(sqlc.narg(ltwwlsupt_ticket_ids)::text[]) = 0
        OR v.ltwwlsupt_ticket_id = ANY (sqlc.narg(ltwwlsupt_ticket_ids)::text[])
    )
    AND (
        sqlc.narg(flag)::text IS NULL
        OR (
            sqlc.narg(flag)::text = 'embargo'
            AND v.embargo = true
        )
        OR (
            sqlc.narg(flag)::text = 'duplicate'
            AND v.duplicate = true
        )
    )
    AND (
        sqlc.narg(search)::text IS NULL
        OR v.vulnerability_id ILIKE '%' || sqlc.narg(search) || '%'
        OR v.component_name ILIKE '%' || sqlc.narg(search) || '%'
        OR v.title ILIKE '%' || sqlc.narg(search) || '%'
    )
GROUP BY v.stage
ORDER BY v.stage;
