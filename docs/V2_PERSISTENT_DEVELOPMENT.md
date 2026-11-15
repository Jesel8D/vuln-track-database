# Database V2: desarrollo persistente y SQL007

Rama `feat/v2-persistent-development-database`, basada en `0cc4dfd719463fb15eb1689a0f46550d9f204a71`. No integra MVP-B ni reescribe SQL001–006.

SQL007 amplía únicamente el CHECK `app_findings_applicability_valid` con undetermined, manteniendo potential/confirmed/not_applicable y todos los datos históricos. Requiere el constraint original exacto y SQL004/005/006; falla ante drift o reaplicación. Usa una transacción con límites de bloqueo/ejecución y valida el nuevo constraint. No modifica RLS, triggers de inmutabilidad, privilegios ni evidencia.

`tests/006_v2_stabilization.sql` es rollback-only: 4 verificaciones de constraint validado, guard de evidencia y RLS/29 políticas. Los otros tests SQL se conservan. El entrypoint de PGDATA vacío añade SQL007 después de006; jamás se ejecuta otra vez sobre un volumen inicializado.

El entorno recomendado se coordina desde Backend `feat/v2-stabilization`, [docs/V2_PERSISTENT_DEVELOPMENT.md](https://github.com/Jesel8D/vuln-track-backend/blob/feat/v2-stabilization/docs/V2_PERSISTENT_DEVELOPMENT.md). Su secuencia nueva real es SQL001/002 → Alembic verificado 0001..0004 → SQL004/005/006/007. No hay migración directa inventada ni stamp a ciegas, y no carga seeds de demo en el volumen de desarrollo.

El helper crea un volumen externo etiquetado, separado de cualquier base existente, y un API login restringido con membresía explícita de los dos grupos técnicos. `vulntrack_registration` permanece NOLOGIN y no es miembro automático de vulntrack_app. Se comprueban catálogo, privilegios y 29 políticas; no se desactiva RLS para crear workspaces.

Para una instalación V2 anterior: backup privado y restauración aislada de ensayo, API parada, verificar catálogo anterior exacto y aplicar SQL007 una vez como operador. No reaplicar SQL001/004/005/006, alterar evidencia histórica, relajar políticas o eliminar constraints a ciegas. El backend actualizado acepta los dos catálogos exactos y sigue rechazando modificaciones desconocidas.

La guía Backend contiene backup `pg_dump -Fc`, checksum, restauración a un perfil/volumen NUEVOS y prueba HTTP de retención y aislamiento. Ni parar los servicios ni repetir pruebas temporales elimina ese volumen. No usar down -v, volume prune o DROP DATABASE para resolver incidencias. El dump contiene hashes/HMAC y debe protegerse; no se incluye en Git.

No es un despliegue productivo. La ratificación global del modelo V2 sigue pendiente.
