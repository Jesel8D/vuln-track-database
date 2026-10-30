-- Datos sintéticos: no son CVE, CPE, personas ni vulnerabilidades verificadas.
-- Repetible sin sobrescribir filas existentes; usar solo para demostración.
\set ON_ERROR_STOP on
BEGIN;
INSERT INTO vulntrack.users (id, username, active) VALUES
('00000000-0000-4000-8000-000000000001', 'demo_operator', false)
ON CONFLICT (id) DO NOTHING;

INSERT INTO vulntrack.assets
    (id, device_type, manufacturer, model, version, site_label, inventory_label, notes)
VALUES
('10000000-0000-4000-8000-000000000001', 'router', 'Marca demo', 'Modelo A', '1.2', 'LAB-1', NULL, NULL),
('10000000-0000-4000-8000-000000000002', 'switch', 'Marca demo', 'Modelo B', '2.0', 'LAB-1', 'INV-DEMO-2', 'Inventario sintético'),
('10000000-0000-4000-8000-000000000003', 'servidor', 'Marca demo', 'Modelo C', '3.0', 'LAB-2', NULL, 'Sin evaluación registrada')
ON CONFLICT (id) DO NOTHING;

INSERT INTO vulntrack.analysis_runs
    (id, asset_id, initiated_by, selected_cpe, status, coverage, started_at, completed_at, source_timestamp)
VALUES
('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001',
 '00000000-0000-4000-8000-000000000001', 'cpe:2.3:a:demo:producto_a:1.2:*:*:*:*:*:*:*',
 'completed', 'complete', '2026-10-01T12:00:00Z', '2026-10-01T12:01:00Z', '2026-10-01T12:01:00Z'),
('20000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000002',
 '00000000-0000-4000-8000-000000000001', 'cpe:2.3:a:demo:producto_b:2.0:*:*:*:*:*:*:*',
 'completed', 'complete', '2026-10-01T12:02:00Z', '2026-10-01T12:03:00Z', '2026-10-01T12:03:00Z')
ON CONFLICT (id) DO NOTHING;

INSERT INTO vulntrack.findings (id, analysis_id, external_id, title) VALUES
('30000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
 'CVE-2026-9999999', 'Hallazgo sintético; no representa una vulnerabilidad real')
ON CONFLICT (id) DO NOTHING;
COMMIT;
