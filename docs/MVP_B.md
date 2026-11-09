# MVP-B — esquema incremental de consulta CVE

Autorización de la misión de Jesel 2026-11-08, desde `80db7fd411f49f648263f275b412384bc49f7ed8`.
Ratificación de Rudi PENDIENTE. D-001/D-002 conservados; no se integró V2,
main, rudi ni audit. SQL V1, privilegios originales y seed originales intactos.

## Artefactos y modelo

Database mantiene `sql/bootstrap_mvp_b.sql`, `init/20-mvp-b.sh`, restricciones,
privilegios y `tests/003_mvp_cve.sql`. `init/10-mvp-a.sh` también reconoce mvp-b
para ejecutar el prerrequisito. Backend mantiene ORM, servicios/API y Alembic
`0004_mvp_cve`; conserva una copia DDL congelada `app/db/cve_schema.sql` que
coincide byte a byte con el cuerpo del bootstrap y un catálogo PostgreSQL
independiente. `mvp_b_manifest.json` fija hashes cruzados. No se añadió tabla:
se extienden `analysis_runs` y `findings`.

| Tabla | Incremento |
|---|---|
| analysis_runs | identification_id/observed_version; idempotency_key/request_hash; total_results/retrieved_count/stored_count/page_count/next_index/retry_count; query_parameters/warning_codes/source_timestamps/page_manifest; failure_code/nvd_cooldown_until |
| findings | evidence; reviewed_by/reviewed_at/review_reason/review_evidence; applicability ampliada |

El CPE existente `selected_cpe` se congela con identificación y versión. La FK
compuesta `(asset_id,identification_id)` impide cruzar activos. El snapshot no
cambia al sustituir la identificación actual. No se rellenan identidades, dueños
ni evidencia del legado por inferencia. Las columnas nuevas permiten null para
legado; sus nuevos contadores parten en 0 y total_results queda null, no equivale
a una consulta recién realizada.

## Integridad

- UNIQUE(asset_id,initiated_by,idempotency_key), par de huella/clave y snapshot
  obligatorios en filas nuevas; trigger exige propietario/identificación actual
  confirmed y coincidencia de CPE/versión al aceptar queued.
- Índice único parcial asset_id para queued/running; índices activo/created_at/id
  y cola creada/ID. Si un legado tiene dos ejecuciones activas, la actualización
  aborta: no se cierran ni borran automáticamente para crear el índice.
- Contadores no negativos, stored<=retrieved, máximo 5 páginas/10 reintentos.
  Objetos/arrays JSON acotados; parámetros 4 KiB, manifiesto 8 KiB/5 páginas,
  avisos 20 y timestamps 5. failure_code controlado, fechas/lifecycle V1 vigentes.
- Estado/cobertura separados. En nuevos terminales complete exige páginas,
  total/almacenados/posición concordantes y ausencia de avisos/fallo; failed
  exige cero páginas y cobertura null. La integridad de ingestión por página y
  autorización de lecturas pertenecen además al servicio Backend.
- Guard de ejecución impide DELETE, cambios de snapshot, modificación de
  terminales, retroceso de contadores y transiciones inválidas. El legado queda
  congelado, no se reejecuta sin evidencia identificada.
- UNIQUE(analysis_id,source,external_id) conserva un CVE por ejecución. Duplicados
  históricos impiden migrar y revierten DDL/marcador; no se fusionan ni borran.
- evidence JSON objeto <=64 KiB y clasificación inicial potential/undetermined.
  Nuevas ingestas solo en ejecución running, estado open, clasificación original
  igual a la evidencia. `not_applicable` requiere revisión humana.
- Revisión exactamente open→reviewed, sobre ejecución terminal: actor propietario,
  fecha, motivo 1–500 y evidencia 1–2000. Ninguna revisión altera CVSS, datos de
  origen o evidencia original. Legado sin evidencia no se reinterpreta.
- Runtime recibe UPDATE solo de progreso y columnas de revisión; no de CPE,
  identidad, hash, evidencia, ni DELETE/TRUNCATE/DDL. Triggers y funciones sin
  EXECUTE PUBLIC. La API conserva autorización individual; esto no introduce RLS
  ni seguridad multitenant de V2.

## Instalación limpia y evolución

Para PGDATA nuevo, configurar `VULNTRACK_SCHEMA=mvp-b` antes del primer arranque:
V1 + privilegios → MVP-A → MVP-B. Default v1 y opción mvp-a conservados.
No basta cambiar esa variable para actualizar un volumen existente. No se
creó ni migró ninguna base personal persistente durante esta misión.

El bootstrap MVP-B deja inventario vacío y no provisiona credenciales. El seed
V1 permanece original y se ensaya antes de migrar en el runner Backend. No
cargarlo después del bootstrap MVP-B: sus INSERT de filas sintéticas sin
identificación serían rechazados por los guards de ingestión nuevos.

Después del bootstrap, reconocer desde Backend con URL de mantenimiento privada:

```bash
python -m app.db.adopt_schema --confirm-proposal --mvp-b
alembic check
python -m app.db.verify_schema
```

En base MVP-A ya reconocida, usar exclusivamente `alembic upgrade head` de Backend.
Desde V1: `alembic -x ownership_proposal=1 -x mvp_a=1 upgrade head`. Catálogo exacto
antes/después, locks coordinados y DDL en transacción. No aplicar de nuevo el
bootstrap ni stamp a ciegas. 0004 no necesita otro opt-in: requiere orden explícita
de mantenimiento y baseline MVP-A válido; no se ejecuta al iniciar API. Esta
compatibilidad permite conservar sin cambios el launcher Web V1.

Runtime usa un login privado no administrativo miembro de vulntrack_app. El
permiso SELECT(password_hash) para autenticación se provisiona por separado,
como en MVP-A, sin secretos dentro del repositorio. Backend ejecuta un worker
SQL por instancia con cuota compartida CPE/CVE local y recuperación; detalles en
[Backend MVP-B](https://github.com/Jesel8D/vuln-track-backend/blob/feat/mvp-b-nvd-cve-backend/docs/MVP_B.md).

Downgrade destructivo bloqueado: retirar columnas/guards perdería identidad,
evidencia o revisión. Una reversión de despliegue con datos nuevos exige una
estrategia de respaldo/restauración revisada; no hay promesa de rollback sin pérdida.

## Pruebas reproducibles

```bash
python3 tests/run_mvp_b.py
python3 tests/run_mvp_a.py
# Desde Backend:
DATABASE_V1_PATH=../database .venv/bin/python scripts/test_postgres.py -q
DATABASE_V1_PATH=../database .venv/bin/python scripts/test_postgres.py --bootstrap-mvp-b -q
```

Los runners Database asignan contenedores propios nuevos con PGDATA tmpfs,
sin puertos, volúmenes persistentes ni red; ejecutan el entrypoint real y solo
detienen el recurso asignado. MVP-B comprueba instalación vacía, metadatos,
FK/unicidad/guards/grants. MVP-A conserva repetibilidad del seed anterior.
Backend añade PostgreSQL real, catálogo/ORM/Alembic, migración con activos,
CPE confirmado e historial, duplicados legado, rollback y concurrencia/API.
No son aserciones de seguridad de V2 ni pruebas de dispositivos.

Resultados finales compartidos en
[Backend MVP_B_RESULTS.md](https://github.com/Jesel8D/vuln-track-backend/blob/feat/mvp-b-nvd-cve-backend/docs/MVP_B_RESULTS.md).
Se mantienen pendientes la revisión conjunta, preparación de producción y
cualquier escala que requiera cuota global entre varios procesos/egresos.
