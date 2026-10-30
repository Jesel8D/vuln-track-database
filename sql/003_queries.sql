-- Consultas de ejemplo; autorización por recurso y paginación pertenecen a API.
\set ON_ERROR_STOP on
SELECT id, device_type, manufacturer, model, version, site_label,
       inventory_label, notes, created_at
FROM vulntrack.assets ORDER BY created_at, id LIMIT 20 OFFSET 0;

SELECT a.id AS asset_id, r.id AS analysis_id, r.status, r.coverage,
       r.selected_cpe, r.source_timestamp,
       CASE WHEN r.id IS NULL THEN NULL ELSE count(f.id) END AS potential_findings
FROM vulntrack.assets a
LEFT JOIN vulntrack.analysis_runs r ON r.asset_id = a.id
LEFT JOIN vulntrack.findings f ON f.analysis_id = r.id
GROUP BY a.id, r.id ORDER BY a.id, r.id;

SELECT f.id, r.asset_id, f.external_id, f.applicability, f.status, f.cvss
FROM vulntrack.findings f
JOIN vulntrack.analysis_runs r ON r.id = f.analysis_id
ORDER BY f.analysis_id, f.id;
