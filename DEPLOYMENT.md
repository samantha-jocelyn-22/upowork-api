# Publicación de UPOwork en Render

Este proyecto incluye `render.yaml` para preparar un servicio web en Render.
La configuración utiliza un disco persistente para SQLite y los CV; el plan
Starter tiene costo y debe confirmarse en Render antes de crear el servicio.

## Antes de publicar

1. Obtén autorización de la UPOTec para publicar el sistema y tratar datos de alumnos.
2. Revisa el aviso de privacidad con la persona responsable de protección de datos.
   El texto incluido es una base y no sustituye una revisión legal institucional.
3. Confirma el correo institucional real para solicitudes de privacidad y soporte.
   Actualiza `contacto.html` y las referencias relacionadas si la dirección de ejemplo
   no existe o no está autorizada.
4. Comprueba que los datos actuales en `upotec.db` sean solo los que deseas conservar.
   No se copian automáticamente a la nueva base del hosting.

## Despliegue inicial

1. Sube el proyecto a un repositorio privado de GitHub. No subas `.venv`, archivos
   CV, claves, ni una base que contenga datos personales. Revisa `.gitignore`.
2. En Render, crea un Blueprint desde el repositorio y revisa los recursos y costos
   descritos por `render.yaml`.
3. En la configuración del servicio, establece `UPOWORK_ADMIN_EMAIL` y
   `UPOWORK_ADMIN_PASSWORD` como variables secretas. La contraseña debe tener al
   menos 12 caracteres. El primer arranque crea esa cuenta como personal docente.
4. Confirma el despliegue y espera a que el servicio indique que está disponible.
5. Inicia sesión con la cuenta administrativa. El personal autorizado registra las
   oportunidades, verifica que continúen vigentes y agrega el enlace al anuncio original.
6. Prueba registro de alumno, aceptación del aviso, carga de un PDF, recomendaciones,
   postulaciones, revisión de sugerencias y controles de permisos.
7. Conecta el dominio desde Render y el registrador del dominio siguiendo los valores
   DNS que Render muestre para ese servicio. No uses valores DNS genéricos.

## Límites de esta configuración

- SQLite y un disco persistente están pensados para una primera publicación de
  bajo tráfico con una sola instancia. Para operación institucional con más usuarios,
  migra a PostgreSQL y almacenamiento privado de archivos antes de escalar.
- El correo para recuperación de contraseña y las notificaciones por email requieren
  configurar y probar un proveedor de correo; no se envían mensajes externos todavía.
- Configura copias de seguridad periódicas del disco y prueba una restauración.
- La aplicación no debe recibir datos reales hasta que la universidad apruebe el
  aviso de privacidad, los permisos de acceso, el plan de respaldo y los responsables.
- No compartas credenciales, contraseñas ni valores secretos; introdúcelos directamente
  en el panel del proveedor de hosting.
