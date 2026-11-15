# SQL008 — verificación persistente, sin habilitar solicitudes remotas

**IMPLEMENTADO CON LIMITACIONES.** Rama feat/v2-security-verification-database,
basada en b377b5b. No se aplicó a la instalación personal. SQL001–007, datos,
columnas, constraints, triggers y 29 políticas RLS anteriores se conservan.

SQL008 se ejecuta una vez sobre SQL007 compatible por mantenimiento autorizado.
Crea el esquema vulntrack_verification y dos tablas: challenges y attempts.
No es un seed, no modifica cuentas/claves y no convierte aprobaciones anteriores
en verificaciones. Antes de aplicarlo: backup verificado y ensayo en copia nueva.
El script es transaccional y acota lock_timeout/statement_timeout. No repetirlo
sobre objetos existentes ni usarlo para resetear datos.

## Modelo y estados

challenges vincula workspace/aplicación/destino por FK compuesta y al emisor por
membresía. Conserva UUID, método https_file, propósito, origen, SHA-256 de URL,
versión/vigencia de declaración, digest del token, Idempotency-Key, estado,
contador/versiones y fechas. No conserva URL completa duplicada, cuerpo o token
en claro, contraseña del sitio ni respuesta HTTP completa.

attempts se vincula a ese scope completo, permite una fila por desafío y registra
actor, procedencia laboratory, lease, resultado, fechas y digest/IP/certificado.
Su identidad y un resultado final son inmutables; no hay borrado para roles de
servicio. Un match de laboratorio no representa control: el resultado es
LABORATORY_MATCH_ONLY, challenge failed, verified_at null. verified está reservado
y ningún procedimiento actual lo genera; el trigger impide transiciones a él.

Límites propuestos: token aleatorio 256 bits generado en Backend, TTL diez minutos,
un intento, lease quince segundos, un pending por destino, veinte emisiones por
workspace/24 h. Las funciones usan reloj de PostgreSQL después de adquirir locks,
serializan cuota y filas y escriben auditoría en la misma transacción. Revocación
es idempotente y auditable; URL/versión/rol/vigencia se vuelven a comprobar. Lecturas
Backend derivan estado efectivo sin inventar fechas ni reescribir estados antiguos.

## Roles y RLS

| Rol | Acceso |
|---|---|
| vulntrack_app | SELECT solo columnas de metadatos; EXECUTE issue/revoke; sin digest ni DML directo |
| vulntrack_registration | Sin USAGE del nuevo esquema y sin funciones/tablas nuevas |
| vulntrack_verification_lab | NOLOGIN/NOBYPASSRLS; SELECT bajo RLS y EXECUTE claim/finish de laboratorio; no se concede a API |
| vulntrack_verification_owner | NOLOGIN/NOSUPERUSER/NOBYPASSRLS, sin miembros, propietario técnico de objetos |

Ambas tablas tienen ENABLE/FORCE RLS. Seis políticas usan workspace actual y
membresía activa del contexto HMAC existente. Viewer solo lee; owner/editor
pueden ejecutar operaciones acotadas. El owner también queda sujeto a RLS.
No hay DELETE/TRUNCATE ni INSERT/UPDATE directos para API o lab. PUBLIC no recibe
EXECUTE y no puede crear objetos en el esquema.

Cinco funciones SECURITY DEFINER tienen propietario técnico y search_path fijo
pg_catalog, con referencias calificadas. Los permisos heredados mínimos del
owner son SELECT de aplicaciones/destinos, UPDATE de una columna exclusivamente
para row locks, REFERENCES para FK, EXECUTE de contexto/validación e INSERT/USAGE
de auditoría. No tiene acceso a context_keys ni privilegio global administrativo.
El superusuario de mantenimiento sigue siendo de confianza. No se usa SQL dinámico.

## Coordinación D-002 y compatibilidad

Database conserva bootstrap canónico sql/008_v2_target_verification.sql y
tests/007_v2_verification.sql. Backend conserva mappings, copia empaquetada exacta
sin envoltorio psql, catálogo de seguridad y Alembic independiente:

```bash
python -m alembic -c alembic-verification.ini upgrade head
```

Su tabla public.alembic_verification_version es independiente de la línea antigua.
Adopta un bootstrap existente SOLO si tablas, tipos, constraints, índices, triggers,
funciones, propietarios, RLS, ACL y roles coinciden exactamente. El ensayo existing
migra desde SQL007; new aplica SQL008 y después comprueba adopción. Drift, grants
inesperados, BYPASSRLS, objetos desconocidos o search_path inseguro bloquean la
adopción. No se hace stamp ciego ni se afloja el catálogo antiguo.

Las 24 comprobaciones SQL nuevas se ejecutan con PostgreSQL real. Backend amplía
tests de JWT/RLS, scopes ajenos, roles, concurrencia, límites, rollback y drift.
Backups/restauraciones de prueba usan volúmenes nuevos, conservan hashes/fechas y
recrean grupos NOLOGIN antes de pg_restore; ninguna restauración pisa el principal.

Rollback conserva este esquema y sus evidencias y vuelve al código anterior.
Downgrade destructivo está bloqueado. Los verificadores antiguos y las lecturas
del código estable/Fase 2A fueron ensayados con el esquema adicional presente.

Pendiente: esquema/procedencia de evidencia operativa real, políticas de retención,
rate limits ratificados, reconciliación de intentos abandonados y aprobación de
equipo. DNS/egreso públicos no demostrados: todas las verificaciones remotas del
servicio y ZAP permanecen bloqueados. Esta documentación no aprueba arquitectura.
