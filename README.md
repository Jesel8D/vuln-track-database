# VulnTrack — PostgreSQL Database V1

Implementación local de la persistencia de usuarios mínimos, activos, evaluaciones NVD y hallazgos potenciales. Incluye soporte de almacenamiento para claves idempotentes; no contiene API, autenticación completa, ORM ni migraciones Alembic. El diseño materializado continúa como **PROPUESTA** técnica provisional para revisión, según la misión de Database V1 del 30-10-2026. D-001 y D-002 permanecen **APROBADA** en el [contexto central](https://github.com/Jesel8D/vuln-track-context/tree/dev/jesel).

## Inicio local

Requiere Docker y Docker Compose con `up --wait`. Desde este repositorio:

```sh
docker compose --env-file .env.example -p vulntrack-dev config --quiet
docker compose --env-file .env.example -p vulntrack-dev up -d --wait postgres
docker compose --env-file .env.example -p vulntrack-dev exec postgres sh -c 'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
```

El ejemplo utiliza una contraseña **solo de desarrollo**, públicamente conocida. No usarlo en un entorno compartido ni producción. Para configuración privada puede copiarse `.env.example` a `.env` (ignorado por Git), cambiar la contraseña y usar `--env-file .env`; esta misión no generó `.env`. Variables: `POSTGRES_DB=vulntrack`, `POSTGRES_USER=vulntrack_owner` (administrador local, no usuario de la aplicación), `POSTGRES_PASSWORD` obligatorio, `POSTGRES_PORT=55432`. El puerto se publica solo en `127.0.0.1`; móvil y web deberán consumir la API, no conectarse a PostgreSQL. El volumen del proyecto persiste al reiniciar o detener. No reutilizar un nombre de proyecto ajeno.

Imagen fija `postgres:16.15-alpine` con digest en [compose.yaml](compose.yaml), **PROPUESTA** de configuración provisional. PostgreSQL 16 está soportado; versión menor y tag se comprobaron el 30-10-2026 en [política oficial](https://www.postgresql.org/support/versioning/) e [imagen oficial](https://hub.docker.com/_/postgres). La imagen efectivamente probada informó PostgreSQL 16.15. Actualizar tag y digest juntos tras revisar notas y probar una copia; no se afirma compatibilidad con un stack backend todavía no seleccionado.

## Orden y estructura

```text
.env.example
.gitignore
compose.yaml
init/00-bootstrap.sh
sql/001_schema.sql
sql/002_privileges.sql
sql/003_queries.sql
seed/001_demo.sql
tests/001_integrity.sql
tests/run.sh
docs/SCHEMA.md
docs/PROVISIONAL_DECISIONS.md
docs/TEST_RESULTS.md
diagrams/database_v1.mmd
```

El entrypoint oficial ejecuta [00-bootstrap.sh](init/00-bootstrap.sh) únicamente con el directorio de datos vacío: primero el [esquema](sql/001_schema.sql), después los [privilegios](sql/002_privileges.sql). Ambos scripts usan transacciones y detienen la ejecución ante error. Los seeds y pruebas **no** se ejecutan al arrancar. No es un mecanismo de actualización de bases existentes. Si falla el primer arranque, comprobar logs y resolver el punto fallido antes de continuar; no borrar el volumen para ocultar el error.

## Demostración y consultas

```sh
docker compose --env-file .env.example -p vulntrack-dev exec -T postgres sh -c 'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -f /vulntrack/seed/001_demo.sql'
docker compose --env-file .env.example -p vulntrack-dev exec -T postgres sh -c 'psql -X -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -f /vulntrack/sql/003_queries.sql'
```

Seed sintético: un usuario inactivo sin contraseña, tres activos, dos evaluaciones y un hallazgo CVE ficticio. Una evaluación tiene cero hallazgos con cobertura completa; otro activo no tiene evaluación y sus resultados se muestran como `NULL`, no como cero CVE. No se hizo consulta a NVD. Las filas usan UUID fijos y `ON CONFLICT (id) DO NOTHING`: repetir seed no sobrescribe datos ni reconcilia filas que hayan cambiado. No usarlo en producción.

## Pruebas

```sh
./tests/run.sh
```

El runner crea un **proyecto nuevo** con puerto local aleatorio y las credenciales ficticias del ejemplo; rechaza proyectos que ya tengan contenedores o volúmenes. Ejecuta integridad, privilegios, consultas, concurrencia de dos transacciones y persistencia tras reinicio y recreación. Detiene al terminar exclusivamente su contenedor y conserva su volumen y red para inspección; imprime el nombre exacto. No borra volúmenes. Las comprobaciones SQL se revierten; la prueba concurrente deja un cuarto activo técnico y su snapshot en ese entorno aislado. Véase [resultados reales](docs/TEST_RESULTS.md).

## Instalaciones existentes y actualización

Con datos existentes, `docker compose up` no reaplica scripts montados. El baseline rechaza un esquema que ya exista en vez de sobreescribirlo. No ejecutar `001_schema.sql` como actualización ni asumir que `CREATE IF NOT EXISTS` detecta diferencias.

Antes de un cambio: identificar proyecto/volumen y versión, generar backup con `pg_dump -Fc`, restaurar en un entorno nuevo y comprobar integridad, revisar cambios SQL y coordinar el contrato backend. No hay upgrade de esquema V2 en este repositorio: está **PENDIENTE** hasta definir cambios; si se adoptan SQLAlchemy/Alembic, modelos y migraciones pertenecen a backend según D-002. La guía no autoriza destruir datos o volúmenes existentes. No ejecutar `down -v` sobre entornos con datos.

## Integración posterior

El [diccionario y relaciones](docs/SCHEMA.md), [decisiones provisionales](docs/PROVISIONAL_DECISIONS.md) y [ER implementado](diagrams/database_v1.mmd) describen la versión exacta. Para backend: aprobar contrato e identidad; provisionar fuera de Git un login con membresía del grupo técnico `vulntrack_app`; usar transacciones parametrizadas y secretos operativos externos; validar CPE y reglas de negocio. El grupo es `NOLOGIN`, no superusuario y no administra esquema ni usuarios. No tiene actualización/eliminación de activos ni lectura de hashes. No implementa autorización por recurso: esa política sigue **PENDIENTE**.

ZAP no se almacena ni ejecuta en V1: `kind='zap_baseline'` se rechaza. Faltan catálogo autorizado, identidad/permisos, red de salida, controles de DNS/redirecciones y pruebas. Tampoco hay sincronización offline ni integración NVD real. Los checks de texto no detectan secretos en notas: la aplicación y los operadores deben respetar la restricción de datos no sensibles.
