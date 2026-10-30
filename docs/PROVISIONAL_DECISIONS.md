# Supuestos y límites provisionales

Cada elección siguiente tiene estado **PROPUESTA** aunque esté materializada para prueba; implementado no significa aprobación formal del producto. La misión actual autoriza construir Database V1 con alternativas mínimas reversibles. D-001 y D-002 permanecen **APROBADA**, sin una justificación original registrada. No se aprueba Python, ORM ni herramienta de migraciones mediante este trabajo.

| ID local | Elección implementada | Motivo y alternativa / pendiente |
|---|---|---|
| DBV1-01 | PostgreSQL 16.15 Alpine con digest, Compose y puerto en localhost. | Entorno reproducible, versión soportada y comprobada; confirmar plataforma, versión de proyecto y ciclo de actualización antes de uso compartido. |
| DBV1-02 | UUID suministrado por aplicación; timestamp servidor por defecto y trigger updated_at. | Coherente con contrato; no se generaron IDs automáticamente en SQL. Retención, eventos de auditoría y borrado funcional pendientes. |
| DBV1-03 | Campos/límites de activos según propuesta; null para opcionales y sin UNIQUE de inventario. | Evita inventar unicidad o un catálogo; normalización/semántica final y API pendientes. |
| DBV1-04 | Username ASCII minúsculas único, usuarios inactivos por defecto y hash opcional con filtro Argon2id. | Mínimo verificable sin autenticación; no obliga identidad local. Política de usernames y criptografía completa deben aprobarse. |
| DBV1-05 | Ejecuciones NVD requeridas con activo/iniciador/CPE; hallazgos NVD potenciales. | Materializa relaciones propuestas; formato CVE, temporalidad y cobertura explícitas. Selección asistida, consultas externas y verificación humana no implementadas. |
| DBV1-06 | ZAP rechazado por CHECK de kind/fuente, sin target_id persistido. | No existe catálogo de destinos ni validación de autorización/egress; su almacenamiento y ejecución requieren diseño seguro y nueva evolución de esquema. |
| DBV1-07 | Tabla técnica de claves idempotentes y snapshot; ventana sugerida 24 h. | Soporte transaccional probado, sin asumir deduplicación entre claves o al caducar. Política y flujo API pendientes. |
| DBV1-08 | Grupo técnico NOLOGIN y FKs restrictivas, sin UPDATE/DELETE de activos para app. | Privilegio mínimo sin implementar roles funcionales o un CRUD no aprobado. Autorización por recurso y login operativo pendientes. |

Referencias de diseño: [contrato central](https://github.com/Jesel8D/vuln-track-context/blob/dev/jesel/docs/ASSET_CONTRACT_PROPOSAL.md), [modelo propuesto](https://github.com/Jesel8D/vuln-track-context/blob/dev/jesel/docs/DATA_MODEL_PROPOSAL.md), [diccionario](https://github.com/Jesel8D/vuln-track-context/blob/dev/jesel/docs/DATA_DICTIONARY_DRAFT.md). Se complementaron con fuentes primarias consultadas el 30-10-2026: [PostgreSQL: constraints](https://www.postgresql.org/docs/16/ddl-constraints.html), [privilegios](https://www.postgresql.org/docs/16/ddl-priv.html), [versiones](https://www.postgresql.org/support/versioning/) e [imagen oficial](https://hub.docker.com/_/postgres).

**PENDIENTE:** aprobación de contrato/esquema global, stack backend, migraciones futuras, autenticación, permisos por objeto, normalización Unicode, política de retención, evolución de CVSS y verificación de hallazgos; idempotencia de aplicación y expiración; disponibilidad/límites de NVD; catálogo y controles para ZAP. Los checks no detectan secretos en texto ni validan íntegramente CPE/CVSS. No hay credenciales de clientes ni dispositivos en demo. No hay garantía de preparación para producción.
