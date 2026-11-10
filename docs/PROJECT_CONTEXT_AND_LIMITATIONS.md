# VulnTrack: contexto del proyecto y limitaciones del MVP

## Contexto

VulnTrack es un proyecto académico para ayudar a organizar la revisión de seguridad de aplicaciones web. Busca concentrar el inventario de aplicaciones, la identificación asistida de sus tecnologías, la consulta de vulnerabilidades conocidas y el seguimiento de medidas correctivas. El objetivo es construir una herramienta manejable para un equipo estudiantil, no sustituir servicios especializados de gestión de vulnerabilidades.

La propuesta considera una interfaz web y móvil que consumen una API. La API será responsable de la autenticación, autorización, validación y coordinación de los servicios. PostgreSQL conserva los datos del inventario y los resultados; los clientes no se conectan directamente a la base.

## Alcance inicial

- Registrar aplicaciones web con nombre, URL y descripción, bajo una identidad autenticada.
- Permitir completar tecnologías y versiones manualmente y, como mejora acotada, sugerir tecnologías a partir de señales públicas del sitio. El usuario confirma las sugerencias.
- Permitir importar manifiestos de dependencias comunes como una mejora posterior, con límites de formato y tamaño.
- Buscar productos/versiones en el catálogo CPE de NVD y mostrar candidatos para confirmación del usuario. NVD consulta vulnerabilidades conocidas; no inspecciona una URL, repositorio o endpoint para descubrir por sí mismo los componentes instalados.
- Consultar y presentar CVE asociados a los CPE seleccionados, indicando fuente, fecha, cobertura y que una coincidencia es potencial hasta validar su aplicabilidad.
- Permitir seguimiento informativo/manual: pendiente, en corrección, corregido o riesgo aceptado. Las recomendaciones orientan al usuario y no ejecutan cambios en sus sistemas.
- Planear análisis web pasivo con OWASP ZAP Baseline únicamente para destinos cuya autorización y propiedad estén verificadas. Este flujo requiere diseño y controles de red antes de incorporarse al MVP implementado.

## Fuera del alcance inicial

- Análisis de repositorios GitHub por proporcionar solo el enlace, análisis de código fuente y análisis automático de archivos arbitrarios.
- Escaneo de redes, equipos, dispositivos o direcciones no registradas y autorizadas.
- ZAP Active Scan, explotación, pruebas de penetración o acciones que modifiquen el objetivo.
- Reparación automática, cambios de servidor, despliegue o actualización automática de dependencias.
- Garantizar que todo hallazgo sea aplicable, que NVD contenga todos los productos o que un resultado sin CVE equivalga a ausencia de riesgo.

## Limitaciones conocidas

1. **Identificación incompleta.** Las señales públicas pueden ocultar tecnologías, ser ambiguas o estar desactualizadas. Un CPE mal seleccionado produce resultados irrelevantes o incompletos; el usuario debe revisar los candidatos.
2. **Cobertura de NVD.** La consulta devuelve información de vulnerabilidades conocidas que coincide con los criterios enviados y con la cobertura reportada por la integración. No es una auditoría del sistema, no demuestra explotabilidad y depende de la disponibilidad, latencia y calidad de datos de NVD.
3. **Cobertura de ZAP.** Baseline es una revisión pasiva acotada; no equivale a una prueba de penetración ni encuentra todas las vulnerabilidades. En Database V1 ZAP aún no se ejecuta ni se persiste.
4. **Seguimiento humano.** El estado de una recomendación lo registra el usuario. “Revisado” no significa “confirmado” y “corregido” no se valida hasta que exista una nueva verificación.
5. **Evidencia y datos sensibles.** Notas y evidencia pueden contener datos que no deben almacenarse, como secretos, tokens o datos personales. Los límites de texto en PostgreSQL no los detectan automáticamente.
6. **Estado del producto.** Database V2 incorpora tablas de aplicaciones, workspaces y RLS/HMAC; la nueva extensión conserva trazabilidad acotada de consultas NVD. El backend integra autenticación y cliente NVD heredados, y se está adaptando al contrato V2. Esto no demuestra integración completa, preparación para producción, ni habilita ZAP.
7. **Arquitectura aún por acordar.** Framework, ORM, migraciones, roles de negocio, multiusuario/tenencia, retención, respaldo y recuperación requieren decisiones del equipo antes de ampliar el esquema.

## Salvaguardas para análisis autorizados

El usuario debe confirmar que controla el dominio o cuenta con autorización explícita antes de solicitar un análisis. El sistema debe limitar destinos a un catálogo aprobado, aceptar HTTPS/HTTP según política, validar DNS y cada redirección, bloquear loopback, redes privadas, link-local y metadatos de nube, aplicar límites de tiempo/tamaño/concurrencia y aislar el ejecutor. No debe permitir que un usuario convierta VulnTrack en un proxy hacia destinos arbitrarios. Hasta implementar y probar estas salvaguardas, el análisis ZAP queda fuera del flujo ejecutable.

## Criterio de éxito del MVP

Una persona autenticada puede registrar una aplicación autorizada, asociar o confirmar tecnologías/CPE, consultar CVE disponibles, entender la cobertura y registrar una medida de seguimiento; el sistema conserva trazabilidad sin afirmar que un hallazgo es automáticamente aplicable ni que el activo está libre de riesgo.

## Próxima evolución de datos

Database V2 separa aplicación, URL, tecnología y workspace. Las consultas NVD se ejecutan desde el backend sobre CPE elegidos y confirmados por el usuario, y guardan cobertura, páginas, huellas y evidencia limitada. No tratar `initiated_by` como autorización: el backend debe establecer el contexto HMAC en cada transacción y la base aplica RLS. Para ZAP, agregar ejecuciones solo tras implementar verificación de autorización, resolución DNS segura, bloqueo de redes internas y redirecciones, límites de recursos y aislamiento del ejecutor. Mantener NVD y ZAP como fuentes distintas.

Este documento fija contexto de trabajo para el MVP; las decisiones de producto, privacidad y arquitectura deben ser revisadas por el equipo antes de considerarse aprobadas.
