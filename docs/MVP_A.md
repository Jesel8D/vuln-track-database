# MVP-A: bootstrap CPE coordinado con Backend

Misión de Jesel 2026-11-08; autorización explícita adicional para versión
desconocida. Ratificación de Rudi PENDIENTE. No se modifica Context ni decisiones
D-001/D-002. Esta rama deriva de V1 `b493fd1`; no integra V2/004 ni audit/rudi.

## Esquema

Se preservan byte a byte `sql/001_schema.sql`, `sql/002_privileges.sql` y seed.
La instalación nueva optativa añade `sql/bootstrap_mvp_a.sql`, ejecutado por
`init/10-mvp-a.sh` solo cuando VULNTRACK_SCHEMA=mvp-a y PGDATA está vacío.
Default=v1 conserva instalación V1. Ninguna variable migra un volumen existente.

- `assets.created_by uuid nullable`: FK RESTRICT users; históricos sin dueño,
  sin inferencias/backfill. Índice (created_by,created_at,id).
- `assets.version` admite null; mantiene CHECK de texto válido cuando se conoce.
- `asset_cpe_identifications` guarda tanto selección como historial; no duplica
  historial en otra tabla. Columnas: id/asset_id, state, cpe_name/cpe_name_id,
  component_kind/observed_version, source/validated_at, recorded_by/recorded_at,
  reason, replaces_id/valid_to, idempotency_key/request_hash.
- Estados confirmed/needs_review; pending es ausencia de fila. source=NVD.
  Checks para componentes, CPE prefix/texto, versión/motivo, huella y fechas.
- PK UUID; FK RESTRICT users/assets; UNIQUE(asset_id,id),
  UNIQUE(asset_id,recorded_by,idempotency_key), FK compuesta para que el reemplazo
  pertenezca al mismo activo. Índices únicos parciales: actual por asset_id y
  sucesor por replaces_id; índice (asset_id,recorded_at,id).
- Trigger de inmutabilidad solo admite cerrar valid_to una vez. Nuevo evento
  necesita actor propietario y predecessor cerrado exactamente en recorded_at;
  needs_review copia snapshot de confirmed. Constraint trigger diferido exige
  un evento actual y ningún cierre huérfano al terminar la transacción.

Runtime: SELECT/INSERT de eventos, UPDATE(valid_to), sin DELETE ni UPDATE de
snapshots. UPDATE(id) en assets habilita SELECT FOR UPDATE; el trigger V1 impide
cambiar el id. No se concede UPDATE(created_by). Autorización de lecturas sigue
siendo responsabilidad de API; V1 no añade RLS ni credenciales para clientes.
NVD/sintaxis no son verificables íntegramente desde SQL: Backend resuelve UUID
oficial y valida CPE antes de insertar. El SQL no prueba presencia del producto.

## Correspondencia D-002

| Database (instalación nueva) | Backend (evolución y modelos) |
|---|---|
| 001_schema.sql + 002_privileges.sql V1 | 0001 reconoce catálogo V1 existente |
| created_by + índice en bootstrap_mvp_a | 0002_asset_owner, sin backfill |
| version nullable + eventos/guards/grants | 0003_mvp_cpe + ORM CPEIdentification |

Backend conserva DDL congelado cpe_table.sql/cpe_guards.sql y un catálogo MVP-A
capturado de este SQL en PostgreSQL independiente; pruebas comparan catálogo y
ORM exactos. Manifiesto Backend fija hashes de este bootstrap y SQL de pruebas.
No se crea una segunda línea de migraciones SQL para instalaciones existentes.

## Instalación nueva

1. Proyecto/PGDATA nuevos con contraseña privada, puerto solo localhost.
2. Elegir VULNTRACK_SCHEMA=mvp-a antes de iniciar Compose; bootstrap automático.
3. Seed opcional conserva activos sin dueño, usuarios demo inactivos y resultados V1.
4. Provisionar login runtime privado con membresía vulntrack_app y permiso
   SELECT(password_hash) exclusivamente para autenticación backend; no al cliente.
5. Desde Backend, URL de mantenimiento privada, ejecutar
   `python -m app.db.adopt_schema --confirm-proposal --mvp-a`.
6. Verificar catálogo y `alembic check`; arrancar API con una instancia/worker.

No crear una instancia persistente durante esta misión. Los pasos anteriores
son guía para una instalación futura expresamente preparada.

## Actualización V1 con datos

Coordinar respaldo/ventana y revisión con ambos desarrolladores. Usar **Alembic
Backend**, nunca reaplicar bootstrap. V1→head:
`alembic -x ownership_proposal=1 -x mvp_a=1 upgrade head`; desde 0002:
`alembic -x mvp_a=1 upgrade head`. Catálogo antes/después, transacción DDL y locks
bloquean drift; downgrade con pérdida de datos está bloqueado. Solo se ensaya
sobre copias PostgreSQL nuevas desechables. Ninguna base persistente se actualizó.

## Pruebas

`python3 tests/run_mvp_a.py`: ejecuta entrypoint real con PGDATA tmpfs,
VULNTRACK_SCHEMA=mvp-a, seed repetido, conteos V1 y tests/002_mvp_cpe.sql.
Contenedor aleatorio nuevo, sin puerto/red/volumen; solo detiene su propio recurso.

Desde Backend con .venv:

```bash
DATABASE_V1_PATH=../database .venv/bin/python scripts/test_postgres.py -q
DATABASE_V1_PATH=../database .venv/bin/python scripts/test_postgres.py --bootstrap-mvp-a -q
```

Comprueba migración con datos V1, adopción limpia, compatibilidad ORM/Alembic,
pruebas SQL V1 y CPE, HTTP, autorización, idempotencia, concurrencia y rollback.
No requiere NVD en pruebas: MockTransport obligatorio. No sumar resultados de
ambas rutas como casos únicos; comparten suite. Ver docs/TEST_RESULTS_MVP_A.md.

## Pendientes

Ratificación de Rudi, revisión cruzada y preparación de despliegue; cuota NVD
compartida antes de escalar; UI móvil/web. MVP-B propondrá identificación
congelada en análisis, consulta CVE, cobertura/evidencia y revisión de hallazgos.
No se implementan esos cambios ni se modifica análisis/findings en esta misión.
