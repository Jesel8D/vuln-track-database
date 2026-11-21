# Dispositivos RC2

El archivo `sql/009_v2_devices.sql` agrega el esquema `vulntrack_devices`
después de SQL008. El repositorio Backend aplica la misma fuente mediante
Alembic `v2_0002_devices` en una transacción de mantenimiento. Los perfiles
RC2 nuevos y el runner desechable ejercitan esa revisión. La revisión principal
V1 sigue en `0004_mvp_cve`. No se hace adopción por nombre ni se aplica SQL009
a RC1 al arrancar la candidata desde su worktree.

El esquema contiene dispositivos, identificaciones CPE, ejecuciones, hallazgos
y medidas. Las claves foráneas compuestas fijan el workspace y dispositivo de
cada relación. El índice parcial permite una consulta en curso por equipo. Las
identificaciones son anexadas y el API carece de actualización de la evidencia
CVE original. La revisión registra su actor, texto, evidencia y transición en
una operación. Se aplican FORCE RLS y permisos por columna. Owner y editor
escriben. Viewer lee. El usuario de la API carece de permisos de DDL, borrado
y truncado para estas tablas.

Los tests SQL `tests/008_v2_devices.sql` verifican catálogo, roles, políticas,
claves e índices sobre una base desechable. Backend prueba además roles y
lecturas reales, carreras de confirmación y recuperación de los datos. Los
dumps se conservan privados y se restauran en otro volumen. No se incluye una
migración de filas V1 a V2 ni un downgrade que destruya el nuevo historial.
