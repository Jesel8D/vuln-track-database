# Resultados MVP-A — 2026-11-08 America/Mexico_City

PostgreSQL16.15 Alpine fijado por digest. No se usaron bases persistentes.

- `python3 tests/run_mvp_a.py`: entrypoint real con VULNTRACK_SCHEMA=mvp-a,
  PGDATA tmpfs, sin red/puerto/volumen; instalación correcta. Seed V1 ejecutado
  dos veces, conserva3 activos sin dueño,2 análisis y1 hallazgo. SQL CPE correcto.
- Runner Backend desde V1 con datos y Alembic: **194 passed**,51.77s; SQL V1 y CPE correctos.
- Runner Backend desde bootstrap limpio y adopción verificada: **194 passed**,51.65s;
  catálogo idéntico a migración/ORM y Alembic sin diferencias.
- Son194 casos únicos repetidos en dos rutas; no sumar como388.
- Tests CPE: nullable version, dueño, actor, permisos mínimos, snapshot inmutable,
  no DELETE, cierre/reemplazo atómico, un actual, sucesor único, integridad referencial,
  concurrencia de claves/cuerpos iguales/distintos y rollback ante fallo.
- Migración V1/0002→0003 preserva OID/datos/resultados, no backfill ni borrados;
  rechaza drift/guards deshabilitados/índices faltantes y adopción incompleta.
- Backend también construyó imagen y pasó smoke HTTP de regresión con UID10001.
- Tests NVD sin red (fixtures verificadas); resolución real de un UUID también
  correcta en comprobación separada, no requerida por pytest.

Contenedores propios detenidos y datos tmpfs descartados; sin tocar volúmenes
preexistentes. El bootstrap V1 original, privilegios y seed no cambian. V2/004
no se incorpora ni ejecuta. Ratificación Rudi PENDIENTE. No habilita producción.

Ver contrato, instalación y actualización en [MVP_A.md](MVP_A.md). Limitaciones:
UI frontend/móvil pendiente, política compartida NVD antes de escalar, consulta
CVE y seguimiento propuestos para MVP-B y no iniciados. La compatibilidad aquí
probada corresponde a Database V1 + Backend V1.3 evolucionados en estas ramas.
