# Database V2: modelo objetivo y migración segura

**Estado: primera migración aditiva implementada, pendiente de ejecución/verificación.** V1 se conserva como baseline. La migración agrega las nuevas tablas y preserva las filas antiguas; no inventa propiedad ni transforma dispositivos en aplicaciones. No ejecutarla en datos importantes sin backup y revisión del equipo.

## Decisiones de modelo adoptadas para el diseño

- El dominio es la aplicación web y sus componentes, no el inventario de dispositivos. Las filas de `assets` de V1 quedan como legado y no se reinterpretan automáticamente como aplicaciones.
- Los datos pertenecen a espacios de trabajo (`workspaces`). Un usuario puede pertenecer a varios espacios y cada espacio puede tener varios usuarios. Las aplicaciones pertenecen a un espacio; los roles iniciales son `owner`, `editor` y `viewer`.
- Las filas de análisis y hallazgos conservan fuente y cobertura. Una coincidencia NVD es potencial; solo una nueva revisión humana puede cambiar su estado de seguimiento.
- Los análisis ZAP quedan para una fase posterior. Registrar un dominio nunca concede autorización para escanearlo.

## Entidades objetivo

| Entidad | Datos y relaciones | Controles requeridos |
|---|---|---|
| `workspaces` | Nombre, creador y tiempos. | Creador debe tener membresía `owner`; baja lógica o política de retención. |
| `workspace_members` | Usuario, espacio, rol y tiempos. | Clave única (espacio, usuario); solo owner gestiona membresías y roles. |
| `applications` | Espacio, nombre, descripción, estado. | FK compuesta a espacio; todas las operaciones deben validar membresía/rol. |
| `application_targets` | URL normalizada y etiqueta; propiedad de una aplicación. | Solo HTTP/HTTPS; no permitir credenciales embebidas; destino verificado y autorización registrada antes de escaneo. |
| `technologies` | Producto, fabricante, versión, CPE opcional, método/confianza de detección y fecha observada. | CPE parseado/validado en backend; conservar fuente y aprobación del usuario. |
| `analysis_runs` | Aplicación/target, tipo (`nvd_cve`, futuro `zap_baseline`), iniciador, estado, fuente, cobertura y tiempos. | FK compuesta que impida mezclar espacios; solo NVD en primera fase; límites de transiciones. |
| `findings` | Ejecución, identificador externo, severidad/datos CVSS originales, aplicabilidad y estado de seguimiento. | Unicidad por ejecución y fuente/ID; CVSS validado al ingerir; evidencia acotada y sin secretos. |
| `recommendations` | Hallazgo, texto/origen, estado (`pending`, `in_progress`, `fixed`, `accepted_risk`), responsable y fechas. | Historial de transición; “fixed” no prueba remediación. No ejecutar cambios automáticamente. |
| `imports` | Tipo de manifiesto, huella, fecha y resumen de dependencias importadas. | Lista permitida de formatos/tamaño; nunca ejecutar contenido importado; restringir acceso. |
| `audit_events` | Actor, espacio, acción, objeto y fecha. | Append-only para rol de aplicación; excluir secretos y payloads sensibles. |

## Brecha crítica de autorización

PostgreSQL no puede inferir la identidad del usuario final cuando todos los requests usan una credencial compartida de API. Un `SET app.user_id = ...` por sí solo **no** es un control confiable: quien posee la credencial puede establecer otro valor. En V2 el backend deberá autenticar al usuario, comprobar membresía/rol en cada operación y usar consultas parametrizadas. RLS puede añadirse como defensa en profundidad solo cuando el contexto de identidad no sea falsificable por el rol de conexión (por ejemplo, conexión autenticada por usuario o una frontera confiable verificada en base de datos). No afirmar aislamiento por fila hasta demostrarlo con pruebas de dos actores.

## Plan de migración desde V1

1. Crear backup lógico (`pg_dump -Fc`) y restaurarlo en un entorno aislado.
2. Crear espacios de trabajo y membresías con una tabla de asignación explícita de usuario/espacio. No deducir propiedad de `initiated_by`: un activo puede tener ejecuciones de varios usuarios y también puede no tener ninguna.
3. Crear las tablas de aplicaciones/targets/tecnologías. No convertir `manufacturer`, `model` o `site_label` de activos en URL o aplicación.
4. Preservar `assets`, evaluaciones e historial V1 en tablas/esquema legado de solo lectura hasta que el equipo confirme su retención o transferencia manual.
5. Añadir constraints y grants, ejecutar pruebas de integridad, aislamiento, restauración y consultas; comparar conteos y hashes antes/después.
6. Cambiar el backend en una fase coordinada. Revocar a la API acceso a tablas legado una vez migrados los lectores. Retener rollback probado.

## Casos adversariales obligatorios antes de publicar V2

- Usuario A intenta leer/modificar aplicaciones, tecnología, hallazgos, recomendaciones, imports y claves idempotentes del espacio B.
- Editor intenta cambiar roles o expulsar miembros; viewer intenta escribir; miembro eliminado reutiliza una sesión existente.
- FK cruzada combina una aplicación de A con un target/tecnología/ejecución de B.
- URL apunta a loopback, IPv4/IPv6 privada, link-local, metadatos cloud, DNS rebinding o redirección hacia esos destinos.
- CPE/CVE/CVSS malformado, JSON desmesurado, texto con secretos, secuencias de control y payloads grandes.
- Reintento idempotente con misma clave y payload distinto; colisión entre usuarios/espacios; carreras simultáneas.
- Usuario de aplicación intenta DDL, `TRUNCATE`, `DELETE`, acceso a hashes, lectura de otras filas o alterar auditoría.
- Migración sobre V1 con datos: mapeo incompleto debe abortar sin borrar ni reasignar filas.

## Estado de implementación

`sql/004_v2_application_model.sql` crea el esquema aditivo en una transacción. `init/00-bootstrap.sh` lo ejecuta en instalaciones limpias después del baseline y los privilegios. Instalaciones V1 requieren una ejecución manual única después de un backup. `tests/002_v2_security.sql` cubre integridad de membresías, referencias cruzadas, URLs y auditoría; está conectado a `tests/run.sh`, pero aún no se ha verificado en Docker. No se publica una migración automática que invente URLs, propietarios o autorizaciones.

La próxima iteración debe validar la sintaxis con PostgreSQL, ejecutar pruebas en un proyecto nuevo, revisar grants y definir un contexto de identidad que permita aislamiento de filas. El modelo de importaciones aún conserva metadatos del archivo; el backend debe registrar las dependencias importadas como filas `technologies` con procedencia.
