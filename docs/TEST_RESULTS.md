# Evidencia de pruebas de Database V1

Ejecución: 30-10-2026. Entorno real: Linux x86_64, Docker Engine 29.8.2, Compose 5.6.0, imagen oficial fijada en Compose, servidor **PostgreSQL 16.15**. No se ejecutaron pruebas contra servicios externos. Comando final: `./tests/run.sh`, salida **0**.

Proyecto final: `vulntrack-v1-test-1793345865-147012`; volumen `vulntrack-v1-test-1793345865-147012_pgdata`. También se ejecutó una primera suite en `vulntrack-v1-test-1793345599-143518`; después se ampliaron verificaciones de TCP, baseline y permisos y se repitió desde otro volumen vacío. Ambos contenedores quedaron detenidos; no se borraron volúmenes ni datos ajenos.

## Implementado y probado

| Requisito / comprobación | Evidencia ejecutada y resultado |
|---|---|
| Instalación limpia y tablas | `compose up --wait` sobre un proyecto sin contenedores/volúmenes previos; cinco tablas, cinco PK y cinco FK verificadas por catálogo. |
| Inicialización segura | Entry point aplicó los dos scripts; reaplicar `001_schema.sql` devolvió SQLSTATE 42P06 y revirtió, sin sobrescribir el esquema. |
| Protección de entornos existentes | Invocar el runner con el nombre del proyecto final ya existente devolvió 1 antes de levantar o detener recursos, con mensaje de rechazo esperado. |
| Seed repetible | Dos ejecuciones consecutivas; un usuario sin contraseña e inactivo, tres activos, dos evaluaciones, un hallazgo sintético. |
| Consultas | Lectura de activos, evaluaciones asociadas y hallazgos por `003_queries.sql`; distinto NULL para activo sin evaluación y cero para evaluación completa sin hallazgos. |
| Integridad | 20 aserciones positivas y 35 rechazos esperados en `001_integrity.sql`, todos completados. |
| Referencias y eliminación | Rechazo de activo/usuario/evaluación inexistentes y protección de historial al borrar filas referenciadas; sin cascadas. |
| Valores inválidos / opcionales | Rechazo de null requerido, vacío, exceso de longitud, espacios extremos, UUID/CVE inválidos y estado/cobertura/tiempo inconsistentes; null opcional aceptado; inventario repetido aceptado. |
| Unicidad | Rechazo de PK, username y ámbito/clave idempotente duplicados. |
| Seguridad técnica | Puerto publicado solo en localhost; TCP acepta credencial ficticia correcta y rechaza incorrecta; reglas host SCRAM. Grupo app NOLOGIN sin administración; no lee hash, ni actualiza/elimina/trunca activos, ni crea objetos. |
| Tiempo / resultados | Trigger actualizado; fecha de creación inmutable; queued/running/completed con cobertura parcial; revisión de hallazgo conserva aplicabilidad potencial. |
| Frontera de alcance | Inserciones/actualizaciones a ZAP y fuente ZAP rechazadas; CVSS ausente conserva null; no se admitió aplicabilidad confirmada. |
| Soporte idempotente concurrente | Dos conexiones escriben activo y registro técnico en transacción; una confirma, la segunda falla con 23505 y revierte su activo; un solo efecto persistido y snapshot recuperable. |
| Persistencia | Conteos `4 activos / 2 evaluaciones / 1 hallazgo / 1 solicitud técnica` iguales después de reinicio y de recrear contenedor con el mismo volumen. El cuarto activo pertenece a la prueba concurrente. |
| Validación estática | `bash -n tests/run.sh`, `sh -n init/00-bootstrap.sh`, `docker compose ... config --quiet`; sin errores. Revisión de enlaces y `git diff --check` antes de entrega. |

## Implementado pero no probado exhaustivamente

No se midieron carga, capacidad, restauración de backup, sistemas operativos o arquitecturas distintos de x86_64. El diagrama ER fue revisado como texto; no se renderizó por falta de Mermaid instalado. No hay porcentaje de cobertura calculado ni afirmación de que cada combinación posible de checks haya sido probada. El filtro de formato de hash no demuestra criptografía, y CPE/CVSS no están validados semánticamente completos.

## Propuesto y pendiente

Elecciones de versión, esquema, username, estados y ventana técnica continúan **PROPUESTA**. La misión autorizó materializar y probar este baseline, no aprobar el diseño global. **PENDIENTE:** API, validación/normalización de entradas, identidad y autorización por recurso, gestión del login backend, cálculo/comparación de huellas, respuesta completa/reconciliación/expiración, prueba de fallo de red real y registro idempotente de extremo a extremo. No existen conexiones móviles o web ni integraciones NVD/ZAP implementadas en esta entrega. No se creó ORM ni migración de aplicación.
