# Database V2: resultados de estabilización — 2026-11-14

Base: `0cc4dfd719463fb15eb1689a0f46550d9f204a71`. Rama: `feat/v2-persistent-development-database`.

SQL001–006 conservan sus bytes; el entrypoint de un PGDATA vacío añade SQL007. La única modificación de estructura es el CHECK de applicability para aceptar undetermined junto a todos los valores históricos; no hay cambios de datos, evidencia, roles, RLS o triggers.

Pruebas realizadas en esta misión con Backend `feat/v2-stabilization`:

- SQL001:55 + SQL002 seguridad:21 + SQL004 bootstrap:6 + SQL005 privilegios:10 + SQL006 estabilización:4 = **96 comprobaciones por recorrido**, en PostgreSQL tmpfs.
- SQL003 adversarial: **27 comprobaciones aprobadas** sobre otro clúster tmpfs.
- Reaplicación de SQL007 rechazada; definición del constraint idéntica antes/después del rechazo.
- Backend completo: **380 passed, 0 failed, 0 skipped**; incluye carreras, registro/login, RLS, conexiones reutilizadas y los cuatro casos nuevos de workspace/CVE originales.
- Newman: 61 solicitudes preparadas, ambas instalaciones completas sin fallos de aserción; la cuenta B no ve datos de A.
- Persistencia real en volumen propio de validación: registro, workspace, aplicación, tecnología, CPE fijo verificado, CVE AND capturado original, hallazgo, revisión undetermined y recomendación conservados tras parar/reiniciar los servicios. Backup pg_dump custom restaurado en OTRO volumen nuevo; login/datos/aislamiento comprobados. Volúmenes de validación retenidos, no se borraron.
- 29 políticas RLS, grupo registration NOLOGIN separado y API login sin privilegios ni propiedad de tablas; no lectura SQL de HMAC por ese login.

No se conectó ni migró una base personal/productiva. Los tests temporales no apuntan al volumen development. No se ejecutó ZAP ni NVD live. Los resultados de React/build/navegador y la clasificación Newman están en el informe Backend de la misma misión. No son resultados históricos reutilizados.

El entorno continúa siendo de desarrollo; la ratificación global V2 sigue pendiente. Guía y comandos: [V2_PERSISTENT_DEVELOPMENT.md](V2_PERSISTENT_DEVELOPMENT.md).
