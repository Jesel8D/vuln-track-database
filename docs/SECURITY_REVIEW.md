# Revisión de seguridad de Database V1

Revisión estática de `vuln-track-database` frente al uso propuesto para VulnTrack. No se ejecutó contra una instancia conectada a datos reales. La suite existente prueba integridad y privilegios básicos, pero no constituye una prueba de penetración ni valida la API (que todavía no existe).

## Hallazgos

### Alto — El rol de aplicación puede leer y escribir datos de todos los usuarios

`vulntrack_app` recibe `SELECT` e `INSERT` amplios sobre activos, ejecuciones, hallazgos y solicitudes técnicas. No hay `owner_id`/workspace en los activos ni políticas RLS; `initiated_by` solo acredita un UUID y no restringe filas. Si se provisiona un login de backend como miembro de este grupo, un error de autorización en la API puede exponer o alterar datos de cualquier usuario.

**Mitigación antes de uso multiusuario:** aplicar autorización en cada consulta de API con el modelo de workspace, probar aislamiento entre dos usuarios y establecer una frontera de identidad verificable si se adopta RLS. No conceder el login de producción hasta implementar y probar el contrato de acceso.

### Alto — El acceso del rol técnico no está limitado por fila

La prueba confirma límites por tabla y columna, pero no intenta ataques entre usuarios. El rol puede insertar una ejecución indicando otro `initiated_by` válido y puede actualizar filas de análisis/hallazgos sin comprobar que pertenecen al actor autenticado.

**Mitigación:** vincular actor, activo, ejecución y hallazgos a un propietario/espacio de trabajo; actualizar solo filas autorizadas y probar lecturas, modificaciones, referencias cruzadas y claves idempotentes con actores distintos.

**Estado tras iniciar V2:** las tablas nuevas incluyen `workspace_id`, claves foráneas compuestas y RLS por workspace/rol. El contexto está firmado con HMAC SHA-256 y expira en 60 segundos; `vulntrack_app` no puede leer la clave y los cambios manuales a los GUC invalidan la firma. Esto evita que una consulta SQL arbitraria use esos GUC para suplantar a otro usuario mientras la clave y el backend estén protegidos. La autenticación, autorización funcional y provisión segura del secreto todavía deben implementarse en el backend. Las tablas heredadas V1 tampoco tienen RLS.

### Medio — Datos arbitrarios sensibles pueden guardarse en notas y respuestas JSON

`notes` acepta cualquier texto de hasta 1000 caracteres; `response_body` acepta JSON arbitrario con un `id` coincidente. Las restricciones no detectan contraseñas, tokens, datos personales ni evidencia excesiva.

**Mitigación:** minimizar datos; limitar/filtrar campos en la API, definir clasificación y retención, no almacenar secretos ni cuerpos completos innecesarios, y controlar acceso a snapshots. Evaluar si la respuesta idempotente puede reconstruirse en lugar de persistir datos libres.

### Medio — El CHECK de CPE valida un prefijo, no la estructura CPE

El esquema admite valores que comienzan con `cpe:2.3:` sin validar sus 11 componentes ni su significado. Una entrada falsa puede generar consultas incorrectas o alimentar logs/URLs sin codificación segura.

**Mitigación:** parsear y validar CPE en la API con una biblioteca adecuada, codificar parámetros de consulta y conservar el valor normalizado y su procedencia. Mantener la limitación documentada en base de datos.

### Bajo — Formato de Argon2id no prueba que el hash sea seguro

La expresión regular acepta parámetros numéricos sin imponer límites, versión exacta de la biblioteca, sal aleatoria o costo mínimo. Además, `password_hash` es nullable y aún no hay autenticación.

**Mitigación:** dejar hash fuera del flujo hasta implementar autenticación; usar una biblioteca mantenida con parámetros aprobados y límite de costo, y nunca tratar el CHECK como verificación criptográfica. La tabla no permite al rol app leer el hash, lo cual es una defensa útil.

## Controles favorables observados

- La aplicación no se conecta directamente desde web/móvil; Compose publica PostgreSQL en loopback.
- El grupo `vulntrack_app` es `NOLOGIN`, no superusuario, no crea bases/roles y no administra el esquema.
- El grupo no puede leer `password_hash`, actualizar ni borrar activos, borrar filas con historial, ni ejecutar ZAP a través del modelo V1.
- Se usan restricciones FK, límites de entrada, timestamps, estados explícitos y valores potenciales para CVE; los ejemplos son sintéticos.
- La contraseña del archivo de ejemplo está declarada solo para desarrollo y documentada como no apta para entornos compartidos.

## Prioridad para completar la base de datos

1. Aprobar contexto, propiedad/tenencia y roles antes de definir el esquema V2.
2. Alinear el modelo al dominio real: aplicaciones web, URLs autorizadas, tecnologías/versiones, importaciones, consultas NVD, ejecuciones ZAP pasivas futuras y recomendaciones/seguimiento.
3. Añadir migraciones versionadas y pruebas de actualización/restauración; no editar el baseline V1 como si fuera una migración.
4. Revisar privilegios por entidad y fila; probar aislamiento entre actores, referencias cruzadas, inyección en API, abuso de idempotencia y exposición de datos sensibles.
5. Solo después integrar backend y conceder credenciales operativas.

## Alcance de la revisión

Fue una lectura estática del esquema, grants, documentación y pruebas existentes. No se ejecutó SQL de explotación, no se intentó acceder a redes/servicios, y no se inspeccionaron dependencias del backend porque todavía no hay código de backend. La base V1 tiene comprobaciones funcionales previas documentadas en `vuln-track-database/docs/TEST_RESULTS.md`; esas comprobaciones no cubren los hallazgos de autorización por fila descritos arriba.
