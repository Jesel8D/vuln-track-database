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

PostgreSQL no puede inferir la identidad del usuario final cuando todos los requests usan una credencial compartida de API. V2 exige HMAC SHA-256 de corta duración sobre usuario, workspace, expiración y nonce. `vulntrack.establish_context` valida firma y membresía para operaciones normales. `vulntrack.establish_new_workspace_context` permite el primer workspace de un usuario activo con firma válida; después la creación de workspace y owner se completa en una transacción mediante las políticas y triggers existentes. Ambas funciones fijan contexto local, y las políticas verifican la firma de nuevo. El secreto no es legible por `vulntrack_app`. El backend debe autenticar al usuario, comprobar permisos, firmar el contexto y usar consultas parametrizadas. La clave HMAC compartida se provisiona por canal secreto y nunca se registra; la seguridad depende de proteger esa clave y el proceso API.

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

`sql/004_v2_application_model.sql` crea las tablas del modelo, clave privada y RLS. `sql/005_v2_nvd_evidence.sql` agrega contexto seguro para bootstrap, idempotencia, progreso paginado, evidencia acotada y transiciones protegidas de análisis/hallazgos; no realiza llamadas externas. `init/00-bootstrap.sh` ejecuta ambos en instalaciones limpias. En instalaciones existentes V1/V2, aplicar cada script faltante en orden tras backup/restauración de ensayo. El administrador transfiere la clave HMAC al gestor de secretos del backend; nunca se incluye en Git. La suite V2 ahora cubre grants, integridad de evidencia y el primer workspace; todavía debe ejecutarse en PostgreSQL desechable antes de integrar cambios en datos persistentes.

La próxima iteración debe validar la sintaxis con PostgreSQL, ejecutar pruebas en un proyecto nuevo y revisar grants y transferencia/rotación de la clave de firma. El modelo de importaciones aún conserva metadatos del archivo; el backend debe registrar las dependencias importadas como filas `technologies` con procedencia.
