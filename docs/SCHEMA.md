# Esquema relacional V1

**PROPUESTA** técnica implementada y contrastable con [001_schema.sql](../sql/001_schema.sql); no reemplaza la aprobación del modelo global. Esquema `vulntrack`, cinco tablas: cuatro entidades de dominio y una tabla técnica. UUID sin generador SQL por defecto: los identificadores deben llegar del servidor de aplicación o de los scripts de demostración. Marcas `timestamptz`; sesión de desarrollo en UTC. API deberá emitir UTC RFC 3339 y decidir formatos al mostrar fechas.

## Tablas y diccionario

| Tabla | Columnas / tipos / obligatoriedad | Restricciones y origen |
|---|---|---|
| `users` | `id uuid` PK; `username text` único y requerido; `password_hash text` opcional; `active boolean` requerido, defecto false; `created_at`, `updated_at timestamptz` requeridos, valor inicial del servidor. | Usuario de VulnTrack, no dispositivo. Username ASCII minúsculas de 1–80 con letras, dígitos, `_`, `.` y `-`, primer carácter alfanumérico: alternativa mínima provisional, no requisito institucional. Hash nullable o formato Argon2id, **sin verificación criptográfica**. La aplicación deberá usar biblioteca auditada y parámetros aprobados; el seed no tiene contraseña ni usuario activo. |
| `assets` | `id uuid` PK; `device_type`, `manufacturer`, `model`, `version`, `site_label text` requeridos; `inventory_label`, `notes text` opcionales; `created_at`, `updated_at timestamptz` requeridos, defecto servidor. | Datos contemplados por contrato; límites 80/120/120/120/120, inventario 120 y notas 1000 caracteres. Requeridos no vacíos; opcionales null o cadena no vacía. `valid_text` rechaza espacios ASCII de extremos; normalización Unicode completa corresponde a la API. Versiones son texto. No se impone unicidad a inventario ni a combinación de fabricante/modelo/versión. |
| `analysis_runs` | `id uuid` PK; `asset_id uuid` FK requerida; `initiated_by uuid` FK requerida; `kind text` requerido, defecto `nvd_cve`; `selected_cpe text` requerido; `status text` requerido, defecto `queued`; `coverage text` opcional; `source_timestamp`, `started_at`, `completed_at timestamptz` opcionales; `created_at`, `updated_at` requeridos. | Solo NVD V1: `kind='nvd_cve'`. CPE requiere prefijo `cpe:2.3:` y máximo 1024; no es parser ni comprobación de existencia del diccionario. Estados `queued`, `running`, `completed`, `failed`; son valores de ejecución, no estados formales de decisiones. Cobertura `complete`/`partial` o null según ciclo. |
| `findings` | `id uuid` PK; `analysis_id uuid` FK requerida; `source text` requerido, defecto `NVD`; `external_id text` requerido; `title text` opcional hasta 500; `applicability text` requerido, defecto `potential`; `status text` requerido, defecto `open`; `cvss jsonb` opcional; `observed_at`, `created_at`, `updated_at timestamptz` requeridos, defecto servidor. | Solo fuente NVD; CVE con patrón `CVE-AAAA-NNNN...`; formato no acredita existencia. `potential` único valor de aplicabilidad hasta aprobar verificación; `open`/`reviewed`, revisión no implica confirmación. CVSS null u objeto: no se calcula, elige versión o convierte escala; contenido debe validarse antes de mostrar. No se impone unicidad global de CVE. |
| `asset_registration_requests` | `user_id uuid` FK; `method text` defecto `POST`; `route text` defecto `/assets`; `idempotency_key uuid`; PK compuesta por esos cuatro campos. `request_hash text` requerido; `asset_id uuid` FK requerida; `response_status smallint` requerido, defecto 201; `response_body jsonb` requerido; `created_at`, `expires_at timestamptz` requeridos, defecto servidor y +24 h. | Solo POST /assets, huella SHA-256 en hex minúscula de 64 caracteres (no la calcula SQL), respuesta 201 y snapshot objeto con `id` no null igual a asset_id. Expiración posterior a creación. Tabla técnica contemplada por propuesta, no quinta entidad funcional ni API idempotente ya implementada. |

## Relaciones y eliminación

- `assets` 1 → 0..N `analysis_runs`, cada ejecución pertenece a un activo.
- `users` 1 → 0..N `analysis_runs`, cada ejecución registra un iniciador.
- `analysis_runs` 1 → 0..N `findings`, cada hallazgo pertenece a una ejecución.
- `users` y `assets` 1 → 0..N `asset_registration_requests`.

Cinco FKs con `ON DELETE RESTRICT`; no hay cascadas. Actualización de PK referenciadas queda protegida por FKs y trigger. Políticas funcionales de actualización/eliminación, retención y anonimización siguen **PENDIENTE**. Administrador técnico puede eliminar filas sin referencias: V1 no es un archivo inmutable ni una política de borrado aprobada.

## Tiempo y cobertura

Trigger `touch_updated_at` mantiene `updated_at` y rechaza cambios de `id` o `created_at` en las cuatro tablas de dominio. Checks exigen updated_at ≥ created_at. En ejecuciones: queued sin inicio/fin/cobertura; running con inicio sin fin/cobertura; completed con inicio, fin y cobertura explícitos; failed con fin, pudiendo fallar antes del inicio. Fin ≥ inicio cuando ambos existen. Es validación de estado actual, no auditoría de cada transición ni máquina de estados completa. Tiempos del evento fuente pueden ser anteriores a la ingestión, por lo que no se exige inicio ≥ creación de fila.

Una selección sin CPE adecuado es una condición anterior a crear una consulta NVD: el esquema no guarda una ejecución NVD sin CPE ni permite inferir la causa de ausencia de ejecución. Consulta completa sin hallazgos, consulta parcial y fallo son distintos. `complete` expresa páginas recuperadas, no exhaustividad de NVD ni aplicabilidad confirmada. Backend debe distinguir esos resultados y conservar trazabilidad de selección.

## Índices justificados

| Índice | Consulta o integridad que lo justifica |
|---|---|
| PK de cada tabla y UNIQUE de username | Identificación, referencias y colisión de usuarios/claves técnicas; PostgreSQL los crea automáticamente. |
| `assets_created_id_idx (created_at,id)` | Listado paginado de activos según contrato y desempate estable. |
| `analysis_runs_asset_started_idx (asset_id,started_at DESC,id)` | Evaluaciones de un activo y soporte de su FK. |
| `analysis_runs_initiated_by_idx (initiated_by)` | Revisión de historial de un usuario y protección de su FK. |
| `findings_analysis_id_idx (analysis_id,id)` | Resultados por ejecución y soporte de su FK. |
| `registration_asset_id_idx (asset_id)` | Identificar el registro técnico asociado a un activo y soporte de FK. |

La PK técnica comienza con user_id y cubre consultas de su FK. Sin índices en fabricante, sitio, JSONB o estado global hasta conocer consultas reales. No se afirma rendimiento medido ni se construye un catálogo espejo de NVD.

## Idempotencia y privilegios

Persistir activo y solicitud en la misma transacción permite que una colisión de clave revierta el segundo activo; se prueba con dos conexiones. El snapshot puede recuperarse después de un resultado incierto. **PENDIENTE backend:** calcular la huella de contenido normalizado, comprobar actor/permiso, comparar huellas, devolver la respuesta original, tratar conflicto temporal y decidir expiración/reconciliación. No hay rutina de registro ni garantía de idempotencia E2E. No borrar automáticamente claves vencidas; 24 h es una propuesta, no contrato acordado.

`vulntrack_app` es grupo NOLOGIN, sin atributos administrativos. Tiene USAGE del esquema, lectura de activos/evaluaciones/hallazgos/solicitudes, INSERT en esas cuatro tablas, lectura de columnas públicas de users y UPDATE limitado a estado/cobertura/tiempos de análisis y estado de hallazgo. No lee password_hash, no administra usuarios, no crea objetos ni actualiza/elimina activos. El dueño de instalación local es superusuario por diseño de la imagen oficial; no debe usarse por la API. No hay RLS ni autorización por recurso, autenticación funcional, roles de negocio o gestión de sesiones. Crear el login operativo y su secreto corresponde a la integración posterior, fuera de Git.
