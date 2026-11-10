# Validación técnica de Database V2

**Resultado: VALIDACIÓN INCOMPLETA.** No supone aprobación arquitectónica, integración de backend ni autorización para producción. La ejecución histórica descrita abajo examinó `54b7644467a1096c011daf3e5c23d7f9a7773f93`, antes de `sql/005_v2_nvd_evidence.sql`; sus resultados no validan esa nueva migración ni el código Backend V2.

## Causa y correcciones

`pg_trigger` unido a `pg_class`, `pg_namespace` y `pg_constraint` confirmó `vulntrack.workspaces_require_owner` sobre `vulntrack.workspaces` y `vulntrack.workspace_members_owner_guard` sobre `vulntrack.workspace_members`: ambos habilitados (`tgenabled=O`), constraint triggers diferibles e inicialmente diferidos, con constraint en esquema `vulntrack`. Los `SET CONSTRAINTS` de la prueba usaban nombres sin calificar, dependientes de `search_path`; se calificaron. No se cambió ningún trigger.

Además, el runner instala V2 antes de `001_integrity.sql`, cuyo catálogo exigía cinco tablas y cinco PK/FK en todo el esquema; V2 añade objetos. Se limita la verificación a las cinco tablas V1 y sus propias restricciones, conservando los conteos exigidos. Sin esta corrección el runner se detenía antes de la suite V2. `tests/003_v2_adversarial.sql` contiene pruebas adicionales: **es destructivo con datos de prueba, confirma transacciones y requiere un clúster exclusivamente desechable y recién inicializado**; no se incorpora al runner general.

## Entorno y reproducción

Docker 29.8.2, imagen local `postgres:16.15-alpine`, contenedor exclusivo con etiqueta `vulntrack.audit=20261105`, `--network none`, sin puertos ni volúmenes y PGDATA en tmpfs. Contraseña efímera de prueba; no se usaron credenciales reales. Inicialización mediante `POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256`. En un clúster recién creado y listo, con variable shell `audit_container` que identifique el contenedor propio:

```sh
for f in sql/001_schema.sql sql/002_privileges.sql seed/001_demo.sql sql/004_v2_application_model.sql seed/001_demo.sql; do
  docker exec -i "$audit_container" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres < "$f" || exit 1
done
for f in tests/001_integrity.sql tests/002_v2_security.sql tests/003_v2_adversarial.sql; do
  docker exec -i "$audit_container" psql -X -v ON_ERROR_STOP=1 -U postgres -d postgres < "$f" || exit 1
done
```

Usar un clúster nuevo, no solo otra base: `vulntrack_app` es un rol a nivel de clúster. Un intento intermedio en otra base del mismo clúster falló por rol ya existente y produjo 46/8/8 comprobaciones antes de abortar; no se cuenta como ejecución satisfactoria. La repetición final usó otro clúster limpio. No se ejecutó `tests/run.sh`: usa Compose, puerto localhost y volumen; tampoco se probaron su concurrencia ni reinicio y recreación en esta misión.

## Resultados observados

| Ejecución final | Aprobadas | Fallidas | Omitidas explícitamente |
|---|---:|---:|---:|
| `001_integrity.sql` | 55 | 0 | 0 |
| `002_v2_security.sql` | 15 | 0 | 0 |
| `003_v2_adversarial.sql` | 25 | 0 | 0 |

Se contaron los avisos `ok -`, no son casos únicos: 003 repite nueve comprobaciones de preparación de 002 y añade 16. No hay instrumentación para cuantificar todos los escenarios ausentes. La ejecución original previa a las correcciones falló en nombre de constraint; otra ejecución inicial de V1 con V2 falló en conteo global y otra con configuración TCP diferente falló en SCRAM: no ocultar esos diagnósticos. Las comprobaciones están limitadas al servidor y datos sintéticos indicados.

El catálogo de instalación limpia mostró 15 tablas, 39 índices, 128 restricciones, 14 triggers de usuario y 29 políticas en `vulntrack`; estos conteos no demuestran corrección individual exhaustiva. Diez tablas nuevas tienen RLS habilitado; cinco V1 no. Ninguna tabla usa FORCE RLS; el propietario fue postgres. `vulntrack_app` carece de superusuario y BYPASSRLS. En `applications`, app tiene SELECT/INSERT, no DELETE; no tiene USAGE del esquema privado y PUBLIC no tiene EXECUTE de `establish_context`. Las funciones `context_is_valid`, `establish_context`, `has_workspace_role` e `is_workspace_creator` son SECURITY DEFINER con search_path configurado. No se han auditado todas las combinaciones de grants, vistas, funciones ni propietarios de despliegue.

## Seguridad verificada y límites

Con rol `vulntrack_app` y datos sintéticos: sin contexto no se leen ni insertan aplicaciones; A y B ven su propia aplicación; UPDATE de B desde A no cambia B y UPDATE propio funciona; DELETE en applications se rechaza por privilegios. El test V2 rechaza escritura ajena y de viewer, referencias cruzadas, alteración de GUC; prueba restricciones de owner. La suite adicional rechaza firma incorrecta, identidad alterada, contexto expirado, no miembro, usuario desactivado y lectura de clave privada. En la misma conexión, contexto instalado con `set_config(..., true)` desaparece tras commit y rollback. Una variable de sesión fijada con SET reaparece tras SET LOCAL; el pool debe usar transacciones y eliminar estado de sesión residual.

Se comprobó también que una firma válida puede reutilizarse durante su vigencia: el nonce no lleva registro de uso único. Se requiere proteger firma y clave, decidir política de replay, provisión y rotación. La firma HMAC y las políticas no protegen tablas V1. Las funciones de contexto exigen membresía antes de establecerla: el arranque del primer workspace mediante rol app necesita diseño y prueba. Dueños de tabla y roles BYPASSRLS pueden eludir RLS, que no está forzado. La configuración y control de credenciales reales siguen pendientes.

## Pendiente antes de integración FastAPI

No se probó 0002 de Backend ni compatibilidad de catálogo Alembic, migración de V1 con datos históricos, rollback/restauración o concurrencia de pertenencias. No se verificaron exhaustivamente INSERT/UPDATE/DELETE en todas las entidades y roles, desactivación durante sesión, caducidad durante transacciones largas, amenazas de SQL arbitrario, matrices de permisos/vistas/errores, ni ciclo de vida de conexiones real de SQLAlchemy. Backend V1.3 no firma ni instala contexto y requiere `assets.created_by`, ausente en V1/V2 sin 0002. Acordar contrato, roles no propietarios, bootstrap, secretos y estrategia para datos históricos; completar pruebas aisladas antes de integrar. Ninguna decisión pendiente queda aprobada por estas pruebas.

## Extensión NVD V2 posterior — pendiente de ejecutar

En 2026-11-09 se añadió `sql/005_v2_nvd_evidence.sql`, funciones de bootstrap/directorio HMAC, restricciones y triggers NVD, además de `tests/004_v2_workspace_bootstrap.sql` y nuevos casos en 002/003. **Esta extensión no se considera validada todavía.** En la sesión de implementación `docker.exe` estaba instalado pero no había daemon en el pipe Docker; PostgreSQL local temporal tampoco pudo inicializarse porque Windows rechazó la creación del token restringido. No se ejecutó ningún test de la extensión. Debe correr en Docker/PostgreSQL desechable antes de aplicarse a datos persistentes.
