# Resultados de registro V2 — 2026-11-13

- SQL001: **55** comprobaciones; SQL002 de seguridad V2: **21**; SQL004 bootstrap: **6**;
  SQL005 de privilegios de inscripción: **10**. Total **92 por recorrido**,0 fallidas.
- SQL003 adversarial sin cambios: **27** aprobadas en otro clúster desechable;
  parte de su preparación repite casos. El nonce admite replay mientras la firma sea válida.
- `tests/run.sh` completo:92 avisos SQL y6 confirmaciones de shell satisfactorias,
  incluidos SCRAM, concurrencia/rollback, persistencia tras reinicio y recreación.
  Se usó una copia pública temporal limitada por permisos de Docker rootless;
  proyecto final `vulntrack-db-test-registration-final-593638f6`, detenido con su volumen conservado.
- Backend integrado: **371** pytest aprobadas sin skips; instalación nueva: **32**
  aprobadas, incluidas carreras entre dos PIDs PostgreSQL y RLS con pool reutilizado.
- Ninguna base persistente existente, seed o política RLS se modificó.

Incidentes: el primer Compose no pudo leer el checkout privado; otro intento agotó
el disco al recrear, después de pasar SQL/reinicio. Ambos se cuentan como fallos de
entorno. Se conservan volúmenes y se retiraron únicamente contenedores propios
detenidos para liberar espacio. La repetición final terminó con salida0.

Informe detallado, comandos, pruebas API y limitaciones: repositorio Backend,
`docs/SELF_SERVICE_REGISTRATION_RESULTS.md`, rama `feat/v2-self-service-registration`.
La implementación es revisable; integración/producción y aprobación global siguen pendientes.
