# Privilegios opt-in de registro público V2

Cambio incremental para revisión, basado en `rudi` `6fa928105d9157fbd78b66a17f8b86f9353857e0`.
No aprueba el modelo global V2 ni modifica D-001/D-002. La implementación FastAPI,
validaciones, hashes, transacción de onboarding y pruebas API viven en Backend,
rama `feat/v2-self-service-registration`. React vive en `feat/v2-registration-web`.

## Cambio exacto

`sql/006_self_service_registration.sql` crea el grupo técnico
`vulntrack_registration`, NOLOGIN, NOSUPERUSER, NOCREATEDB, NOCREATEROLE,
NOREPLICATION, NOBYPASSRLS. Concede exclusivamente INSERT sobre las columnas
`id, username, password_hash, active` de `vulntrack.users`.
No concede UPDATE/DELETE, lectura de hashes, timestamps, DDL, permisos de red ni
administración de otros usuarios. No añade campos, índices o tablas y no cambia
RLS, triggers, datos, semillas ni SQL histórico001–005.
El rol existente `vulntrack_app` no recibe esa membresía automáticamente.

Un operador autoriza el login API concreto una sola vez, con la API aún apagada:

```sql
GRANT vulntrack_registration TO tu_login_api;
```

Ese login ya requiere su pertenencia a `vulntrack_app`, CONNECT, y el permiso
específico de lectura de `password_hash` usado por el login existente. No debe ser
propietario de esquema/tablas, superusuario ni tener BYPASSRLS/CREATEROLE.
El cliente HTTP no recibe credenciales SQL ni puede elegir el rol de su cuenta.
El propio rol SQL no impone política de fortaleza ni administra el usuario HTTP:
esa frontera corresponde a la API autenticadora y sus validaciones parametrizadas.

SQL006 falla si falta la función bootstrap de SQL005, si ya existe ese rol o si
el operador no puede crearlo. Todo el script es transaccional. No usar DROP ROLE,
IF EXISTS ni alterar roles a ciegas para superar un fallo. Los roles son del
clúster: una segunda base en el mismo clúster requiere inspección y coordinación
de los grants específicos, no recrear el rol automáticamente.

Para cerrar inscripciones: `REGISTRATION_ENABLED=false` en Backend y reiniciar de
forma controlada. Se puede revocar la membresía del login sin borrar cuentas ni
workspaces. No hay downgrade que elimine datos ni automatización de borrado.

## Instalación nueva y compatibilidad heredada

El entrypoint, solo con PGDATA vacío, añade SQL006 después de001/002/004/005.
El backend rudi también conserva rutas MVP-B que requieren Alembic0002/0003/0004.
El verificador Backend nuevo reconoce exactamente el delta SQL004/005 (incluidas
29 políticas), valida el baseline original y aplica las revisiones heredadas.
No ejecuta `create_all`, no recrea tablas V2 ni hace un stamp a ciegas.
Después del upgrade validado, `alembic check` debe indicar que no hay operaciones
pendientes; jamás aceptar una propuesta que elimine las tablas V2.

Los seeds V1 son sintéticos y opcionales. En los ensayos se ejecutan dos veces
**antes** de las migraciones MVP-B; la evidencia histórica se conserva después.
Reejecutarlos después de MVP-B entra en conflicto con guards de ejecuciones
terminales. Ese límite preexistente se documenta; no se cambia el seed para
ocultar el conflicto. Un usuario nuevo nunca recibe ni ve esos activos sin dueño.

## Instalación existente: procedimiento de revisión

No se aplicó nada sobre datos persistentes en esta misión. Antes de integrar:

1. Identificar rama/hash, clúster/base/login, versiones y propietarios reales.
2. Obtener backup y restaurarlo en una base aislada. Probar allí primero.
3. Si parte de V1/MVP, usar el verificador Alembic backend antes del baseline y
   upgrade0004; aplicar SQL004/005 si aún no existen, una sola vez.
4. Si V2 ya existe pero falta la extensión MVP, usar el verificador actualizado
   antes de Alembic0001..0004. Un delta inesperado bloquea el procedimiento.
5. Revisar SQL006, aplicarlo como operador a la copia y conceder la membresía solo
   al login API previsto. Verificar sus privilegios efectivos y los negativos.
6. Configurar HMAC/JWT privados y registro opt-in. Probar `/ready`, registro,
   login, `/auth/me`, workspace propio y denegación cruzada con la cuenta API real.
7. Revisar transacción, concurrencia y rollback; nunca probar con credenciales de
   usuario superadministrador como si fueran las de la API.
8. Integrar en una ventana administrada únicamente después de revisión/aprobación,
   con respaldo y validación posterior. No borrar volúmenes para ocultar errores.

En Backend, las comprobaciones usan `MIGRATION_DATABASE_URL` privada del operador:

```bash
python -m alembic heads
python -m alembic -x ownership_proposal=1 -x mvp_a=1 upgrade head
python -m alembic check
```

Estos son procedimientos de mantenimiento, **no una autorización para ejecutarlos
sobre una base persistente**. El rol/grants de Database no requieren inventar otra
revisión Alembic ni mantener dos definiciones de tablas incompatibles. Nuevas
migraciones estructurales seguirán perteneciendo a Backend según D-002.

## Verificación reproducible

Con los repositorios hermanos y dependencias instaladas, desde Backend:

```bash
python -m scripts.test_v2_registration --installation existing --full
python -m scripts.test_v2_registration --installation new
```

Los runners rechazan fuentes SQL001/002/004/005 distintas del manifiesto auditado,
crean PostgreSQL16.15 desechable nuevo, y ejecutan:

- `tests/001_integrity.sql` antes de migrar; sin editarlo en esta misión.
- `tests/002_v2_security.sql` y `tests/004_v2_workspace_bootstrap.sql` existentes.
- `tests/005_self_service_privileges.sql` nuevo, rollback-only, sin contraseñas.
- Registro HTTP, Argon2id, JWT, usuario activo, owner/FKs diferidas, carreras,
  rollback de fallo y aislamiento SQL/API con un pool de una conexión reutilizada.
- Denegación de contexto falsificado y firma caducada/errónea; sin desactivar RLS.

No son pruebas de una instalación persistente, de recuperación de backups ni de
certificación completa de NVD/V2. Resultados exactos y limitaciones están en
Backend `docs/SELF_SERVICE_REGISTRATION_RESULTS.md`.
