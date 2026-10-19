# Seguridad y privacidad de UruArregla

Última evaluación: **28 de agosto de 2026**
Alcance: la aplicación de escritorio tal como existe hoy.

> Este documento describe controles implementados y verificados, y los riesgos que
> siguen abiertos. **No afirma que el sistema sea invulnerable, ni que esté
> certificado bajo ninguna norma.** Alinearse con controles de un estándar no es
> estar certificado: la certificación requiere una auditoría externa formal que no
> se ha realizado.

---

## 1. Arquitectura real

Saber qué NO existe es la mitad de un modelo de amenazas honesto.

| Componente | Estado |
|---|---|
| Aplicación de escritorio | **Existe** — Tauri 2 (Rust) + React 19 + TypeScript |
| Servidor / API | **Existe** — Supabase: dos funciones RPC para la licencia (§3) y cuatro tablas con RLS para las cuentas y la sincronización (`docs/NUBE.md`) |
| Base de datos | **Licencias + talleres** — `licenses` con RLS sin políticas, y `talleres` / `miembros` / `invitaciones` / `documentos` con políticas por membresía |
| Autenticación de servidor | **Existe** — Supabase Auth (correo y contraseña). La aplicación nunca ve ni guarda una contraseña |
| Almacenamiento en la nube | **Existe** — los datos del taller se sincronizan como texto, clave por clave, dentro de `documentos` |
| Docker / CI/CD | **No existe** |
| Aplicación móvil | **No existe** — la versión web instalable cubre el teléfono |

**Toda la lógica de negocio sigue corriendo en la máquina del taller.** El servidor
no calcula nada: guarda, controla quién puede leer qué, y sella la hora. La
aplicación funciona entera sin conexión y sincroniza cuando puede.

**Lo que esto cambió respecto de la versión anterior de este documento**: ya no es
cierto que "ningún dato del taller sale del equipo". Sale, cifrado en tránsito
(TLS), hacia un proyecto de Supabase, y queda ahí en reposo sin cifrado de
aplicación. Quien evalúe el producto tiene que saberlo: es el precio de que el
teléfono del técnico vea la misma orden que el mostrador. Un taller que no lo quiera
puede seguir usando la aplicación sin cuenta, y ahí nada sale.

**Consecuencia que sigue vigente**: quien tiene acceso físico o de sesión a la
máquina tiene acceso a todo lo que la aplicación muestra. Los controles de abajo
reducen el daño del uso indebido cotidiano; no protegen contra un atacante con la
máquina en la mano.

---

## 2. Modelo de amenazas (STRIDE)

| Amenaza | Superficie real hoy | Control |
|---|---|---|
| **Spoofing** | Suplantar a un miembro del taller | Supabase Auth (correo + contraseña, hash del proveedor); caducidad de sesión local (30 d / 12 h); el operador firma cada asiento |
| **Tampering** | Importación de respaldo JSON; `localStorage`; texto tecleado en los campos | Validación con esquema Zod sobre el JSON crudo; `deepMerge` bloquea claves de prototipo; `Field` saca caracteres invisibles y bidi y limita el largo (`src/lib/sanitize.ts`) |
| **Repudiation** | Acciones sin trazabilidad | Bitácora por orden con actor y hora; consulta de la clave del equipo registrada |
| **Information disclosure** | Comprobantes impresos; artefacto distribuido; clave del equipo | Costos internos nunca salen al cliente; sin mapa de fuentes en el instalador; clave tapada por omisión |
| **Denial of service** | Fallo de render → pérdida del día de trabajo | `ErrorBoundary` en dos niveles |
| **Elevation of privilege** | Leer o escribir el taller de otro; que un técnico se dé permisos | RLS por membresía en las cuatro tablas; sólo el dueño invita y cambia roles (`es_dueno`). El detalle fino por rol lo aplica el cliente: ver §7 |

---

## 3. Controles implementados y verificados

### Ejecución de contenido
- **CSP estricta** en `src-tauri/tauri.conf.json`: `script-src 'self'` sin `unsafe-eval`,
  `object-src 'none'`, `base-uri 'self'`, `form-action 'none'`, `frame-ancestors 'none'`.
- **Protocolo de assets desactivado** (`assetProtocol.enable: false`).
- **Permisos de Tauri mínimos** (`capabilities/default.json`): sin `fs`, sin `shell`,
  sin `http`. Sólo control de ventana, porque la barra de título es propia.
- Verificado: cero `eval`, `new Function`, `innerHTML`, `dangerouslySetInnerHTML`,
  `document.write` en todo el código (`npm run security`).
- **Todo `window.open` lleva `'noopener,noreferrer'`** y el `<iframe>` del visor de
  ayuda lleva `referrerPolicy="no-referrer"`: una pestaña nueva no recibe handle a
  `window.opener` ni la URL de origen. Ocho llamadas revisadas
  (`agenda`, `customers`, `purchases`, `suppliers`, `modals`, `Ayuda`).

### Copia de seguridad cifrada (desde 28/08/2026)
El archivo que sale del equipo va cerrado. Detalle de uso en
`docs/CIFRADO.md`; acá la parte de seguridad.
- **Frase de respaldo** (`src/lib/passphrase.ts`): seis palabras al azar de una
  lista de más de 1024 (`src/lib/palabras.ts`), ≈ 64 bits. Se genera al primer
  arranque, se muestra una vez —modal que hay que confirmar— y vive en
  `ua.backup.pass`. La lista es pública por diseño; lo secreto es la combinación.
- **Cifrado** (`src/lib/crypto.ts`): PBKDF2-SHA-256 con **600 000 iteraciones** y
  sal de 16 bytes por archivo → AES-256-GCM con IV de 12 bytes por archivo. Todo
  con `crypto.subtle`, sin dependencias nuevas. La etiqueta GCM detecta cualquier
  alteración: un archivo tocado no se descifra, no se descifra "a medias".
- **Qué cubre:** el `.uruarregla` en un pendrive, la copia automática diaria que
  OneDrive sincroniza sola, el archivo mandado por correo. **Qué NO cubre:** el
  equipo. La frase está en `localStorage`, al alcance de quien tiene la sesión de
  Windows abierta —la misma frontera que ya asume todo el sistema—. El cifrado
  cierra el viaje del archivo, no la máquina.
- **La copia automática diaria** (`src/lib/autoBackup.ts`) pasó a escribirse
  cifrada con esa frase, con extensión `.uruarregla`. La rotación de 14 sigue
  igual y también barre los `.json` en claro que hayan quedado de antes.
- **Restaurar** fuerza `ua.demo='false'`: el equipo destino queda con la lista
  real completa, no con parches sobre una demostración regenerada.
- **Regenerar la frase** (Ajustes, con confirmación) invalida a propósito las
  copias hechas con la anterior: la frase ES la clave, no hay otra forma.
- **Sigue disponible** la exportación **sin cifrar** (`.json`) como opción
  secundaria, con su advertencia, para diagnóstico y migraciones a mano.

### Saneamiento de entradas de texto (desde 28/08/2026)
`src/lib/sanitize.ts` reúne el saneamiento en un módulo con nombre en vez de dejarlo
disperso. Cubierto por 14 pruebas (`src/lib/sanitize.test.ts`).
- **`limpiarInvisibles`** saca controles C0/C1, espacios de ancho cero, marcas y
  overrides bidi (`U+202A`–`U+202E`, aislantes `U+2066`–`U+2069`) y el BOM. Son los
  caracteres con los que se disfraza un texto —un nombre que se lee al revés, un
  campo que parece vacío— o se rompe un comprobante impreso.
- **`Field`** (`src/components/ui/Field.tsx`, el primitivo de todos los campos de
  texto de la app) llama a `limpiarInvisibles` en cada tecleo y pone un tope de
  5000 caracteres por omisión. Sin el tope, pegar megas en un campo llena la cuota
  de `localStorage` y a partir de ahí no guarda nada.
- **`textoLimpio` / `textoMultilinea`** normalizan espacios y saltos y recortan a un
  largo máximo, para los límites donde el valor se guarda o se imprime.
- **`hrefSeguro`** deja pasar sólo `http:`, `https:`, `mailto:` y `tel:` (y rutas
  relativas), y rechaza `javascript:`, `data:`, `vbscript:`, `file:` y `//host`. Es
  defensa en profundidad: hoy ningún enlace de la app sale de una URL que escriba el
  usuario —los de WhatsApp se arman con `https://wa.me/` fijo y número sólo de
  dígitos—, pero cualquier campo de enlace futuro tiene por dónde pasar.
- **`telefonoLimpio` / `soloDigitos`** dejan el teléfono en dígitos y separadores; el
  número que llega a `https://wa.me/` ya venía saneado por `whatsappNumber`.
- La inyección de fórmula en CSV exportado ya estaba cubierta aparte: `csvCell`
  (`src/lib/csv.ts`) antepone `'` a toda celda que empiece con `= + - @` o tab.

### Imágenes que entran (fotos de equipos, logos, avatar)
Es la única entrada de archivos del sistema.
- Tope de 8 MB antes de procesar.
- **Validación por decodificación real**, no por extensión: `createImageBitmap` falla
  con cualquier archivo que no sea una imagen.
- **Re-codificación a JPEG a través de `<canvas>`**: el archivo original nunca se
  guarda. Esto descarta metadatos, cargas polyglot y cualquier script embebido en un
  SVG, porque lo que se conserva son píxeles.
- Cuotas por orden (12 fotos, 3 MB) para que una carga masiva no llene el disco.

### Datos sensibles
- **La clave de desbloqueo del equipo del cliente está tapada por omisión.** Mostrarla
  es un acto deliberado que queda asentado en la bitácora de la orden con actor y hora.
  Es el único dato del sistema cuyo mal uso perjudica al cliente y no al taller.
- **Los comprobantes del cliente nunca llevan costos internos** ni la clave del equipo.
  Cubierto por 11 pruebas automatizadas.

### Sesión
- Caduca por edad: 30 días con «mantener iniciada», 12 horas sin ella.
- Se comprueba al arrancar y cada 5 minutos con la aplicación abierta.
- Una sesión vencida se borra del disco, no se deja para el próximo arranque.
- Una fecha de inicio en el futuro (reloj movido) cierra la sesión.

### Integridad de la configuración
- La importación de respaldos valida el **JSON crudo** contra el esquema antes de
  fusionar nada. Probado contra 11 cargas hostiles y 5 de contaminación de prototipo.
- `deepMerge` ignora `__proto__`, `constructor` y `prototype`.

### Manejo de errores
- Cero `console.*` en el código de producción salvo el `ErrorBoundary`, que registra
  el mensaje y el componente — **nunca datos del cliente**.
- Ningún mensaje de excepción llega al usuario: todos los textos de error están
  escritos a mano.
- `ErrorBoundary` en dos niveles. El interno deja en pie la navegación, para que un
  fallo de pantalla no obligue a recargar — que en esta aplicación borra el día.

### Cadena de suministro
- `npm audit`: **0 vulnerabilidades** (21/08/2026).
- 12 dependencias de producción, todas de primera línea y mantenidas.
- `package-lock.json` presente y versionado.

### Canal de actualización (desde 27/08/2026)
- Cada instalador se firma con una clave **minisign** propia; la
  clave pública viaja dentro del binario instalado
  (`plugins.updater.pubkey`).
- El plugin verifica la firma **antes** de ejecutar nada. Un
  instalador alterado en tránsito, o servido por otro, se rechaza.
- La clave privada vive fuera del repositorio (`~/.tauri/`) y como
  secreto de CI. `.gitignore` cubre `*.key`, `*.pfx` y `*.p12`.
- La actualización **nunca se instala sola**: se avisa y la persona
  elige el momento (`src/lib/updates.ts`).

> **Riesgo concentrado.** Quien obtenga la clave privada del
> actualizador puede publicar código que se instala en todas las
> máquinas con UruArregla. Es el activo más sensible del proyecto:
> más que cualquier dato de un taller concreto. Su respaldo y su
> custodia están en `docs/DISTRIBUCION.md`.

### Canal de activación de licencia (desde 27/08/2026)
- Al primer arranque la aplicación pide una **clave de licencia** y la
  verifica contra Supabase (`src/lib/licenseApi.ts` → funciones
  `activate_license` / `check_license`). Es la única llamada de red a
  un servicio propio en toda la aplicación.
- **Qué viaja:** la clave y un identificador de equipo al azar
  (`ua.device`, un UUID — `src/lib/deviceId.ts`). **Ningún dato del
  taller ni de sus clientes.**
- La **anon key** de Supabase es pública por diseño y va dentro del
  instalador. La tabla `licenses` tiene **RLS habilitado y sin
  políticas**: con esa key no se puede leer ni escribir la tabla,
  sólo ejecutar las dos funciones `security definer`, que devuelven
  una fila por llamada.
- **Sin conexión no bloquea:** con una clave ya activada, la app
  confía en la última verificación hasta el vencimiento más 7 días de
  gracia. Vencida y pasada la gracia, no deja entrar — **pero no
  borra ni toca nada**: los datos quedan esperando la renovación.
- **Límite honesto:** un control de licencia que corre en el cliente
  es evitable por alguien decidido a parchear el binario. Sube el
  costo, no lo vuelve imposible. La barrera real llega cuando la
  sincronización y el multiusuario exijan una sesión válida contra el
  servidor (§7, hallazgo 5).
- El CSP ya contempla el destino: `connect-src … https://*.supabase.co`
  en `src-tauri/tauri.conf.json` y `vite.config.ts`. No hay permisos
  de Tauri nuevos: es un `fetch`, no el plugin `http`.

### Asistente Uru — clave de Gemini incluida (desde 27/08/2026)
- La sección **Uru** (`/uru`, `src/lib/uru.ts`) es un chat que llama
  **directo a `generativelanguage.googleapis.com`** (Google Gemini)
  con una **clave que se compila adentro del paquete** desde el `.env`
  (`VITE_GEMINI_API_KEY_ENC`, ofuscada con `scripts/gemini-obfuscar.mjs`).
  Todas las instalaciones usan la misma clave; el técnico no carga
  nada.
- **Qué viaja:** el texto de la conversación (lo que escribe el
  técnico y el historial). **Ningún dato del taller** de forma
  automática — pero lo que el técnico pegue en el chat, sí sale.
- **La clave incluida NO es secreta.** La ofuscación (XOR + base64 con
  sal fija en el código) sólo evita el `AIza…` en claro; el paquete
  se puede leer. **Mitigación real:** cuotas por día/minuto en Google
  Cloud, restringir la clave a la API "Generative Language", y
  **rotarla + rebuild** si se detecta abuso. Es la misma postura que
  la anon key de Supabase: pública por diseño, contenida por límites
  del lado del servicio.
- **Salida:** `ua.uru.key` guarda una clave propia opcional que tiene
  prioridad sobre la incluida (para cuando la compartida topa el
  límite). **No** entra en las copias de seguridad
  (`EXCLUIDAS` en `src/lib/backup.ts`).
- El CSP contempla el destino en `src-tauri/tauri.conf.json` y en
  `webCsp()` de `vite.config.ts`. Es un `fetch` con streaming, sin
  plugin de Tauri. Detalle completo en `docs/URU.md`.

### Acceso a disco (desde 27/08/2026)
- La copia de seguridad automática es lo único que escribe fuera del
  navegador. El permiso está **acotado por alcance** en
  `src-tauri/capabilities/default.json` a
  `Documentos/UruArregla/Copias`: la aplicación no puede leer ni
  escribir en ningún otro lado del disco, ni siquiera si alguien
  lograra ejecutar código dentro de la ventana.
- La limpieza de copias viejas sólo borra archivos que coinciden con
  el patrón de nombre propio (`uruarregla-auto-AAAA-MM-DD.json`). Un
  archivo ajeno en esa carpeta no se toca.
- **La sesión abierta (`ua.session`) no entra en la copia.** Es de la
  persona y del equipo, no del taller: restaurar en otra máquina la
  dejaría con la sesión de quien hizo el respaldo, y todo lo asentado
  ahí saldría firmado con su nombre.
- La copia **no está cifrada** y contiene datos personales de
  clientes (nombre, documento, teléfono, dirección). Quien la guarde
  es responsable de dónde la deja. Ver la sección de marco legal.

### Superficie de la versión web (desde 27/08/2026)
- `npm run web:build` produce un sitio estático con su propia CSP
  calculada en compilación (`vite.config.ts`), incluido el hash del
  único script en línea.
- `frame-ancestors` **no** está en esa CSP: en `<meta>` el navegador
  la ignora. Tiene que ir como cabecera del servidor, junto con HSTS
  y `X-Content-Type-Options`. Ver `docs/DISTRIBUCION.md`.
- El trabajador de servicio (`public-web/sw.js`) sólo cachea recursos
  del mismo origen y sólo peticiones `GET`; el documento va siempre a
  la red primero, para que una versión con un fallo se pueda
  reemplazar.
- **Cada navegador es un almacén separado.** La versión web no ve los
  datos de la instalación de escritorio ni al revés, y la pantalla de
  entrada lo dice.

---

## 4. Inventario de datos

### Lo que persiste en el equipo (`localStorage`)

| Clave | Contenido | ¿Personal? | Retención |
|---|---|---|---|
| `ua.session` | Correo y nombre del operador, inicio | Sí — del operador | Caduca: 30 d / 12 h |
| `ua.avatar` | Foto del operador (JPEG 256 px) | Sí — del operador | Hasta que la borre |
| `ua.settings` | Datos del taller, identificador fiscal, logo, medios de cobro | Del negocio | Indefinida |
| `ua.supplierLogos` | Logos de proveedores | No | Indefinida |
| `ua.backup.pass` | Frase que cifra las copias de seguridad (§3) | Clave — no personal | Hasta regenerarla |
| `ua.theme`, `ua.installed`, `ua.sidebar`, `ua.backup.pass.seen` | Preferencias de interfaz y marcas de "ya visto" | No | Indefinida |

### Lo que persiste y además VIAJA

Órdenes, bitácora, pagos, clientes, ventas, caja, inventario, presupuestos,
proveedores, compras, agenda y notas se guardan en el equipo (`ua.*`) y —cuando hay
una cuenta conectada— se sincronizan con el taller en Supabase, clave por clave, como
texto. El detalle de qué viaja y qué se queda está en `docs/NUBE.md` §4 y, en código,
en `src/lib/nube/claves.ts`.

**Esto invalida una afirmación que este documento hacía antes**: ya no es cierto que
no haya datos personales de clientes en reposo, ni que no haya transferencia fuera
del equipo. Los hay, en el equipo y en el servidor.

Se quedan siempre en el equipo, y no viajan nunca: la sesión abierta, el
identificador de la máquina, el tema claro/oscuro, la clave de Gemini cargada a mano
y **la frase que cifra las copias de seguridad** —esta última es lo que impide que un
respaldo robado se pueda abrir, y mandarla al servidor le daría al servidor las dos
mitades—.

### Datos personales que el sistema maneja

Nombre, teléfono, IMEI, número de serie, fotos del equipo y **clave de desbloqueo**.
El IMEI identifica un dispositivo de forma única y la clave abre el teléfono entero:
son los dos datos que exigen más cuidado el día que exista persistencia.

### Marco legal aplicable

El taller de referencia opera en **Uruguay**, donde rige la **Ley 18.331 de Protección
de Datos Personales** y su Decreto 414/009, bajo la URCDP. La aplicación está
globalizada (80 países), así que un taller en la UE quedaría bajo **RGPD** y uno en
Brasil bajo **LGPD**.

**Lo que hoy se cumple por diseño**: minimización (no se pide nada que el taller no
use) y finalidad específica.

**Lo que cambió con la nube**: sí hay transferencia a un tercero —el proveedor de
infraestructura (Supabase)— y hay que decirlo. La región del proyecto se elige al
crearlo; para un taller uruguayo o brasileño, São Paulo mantiene los datos en la
región. Un taller de la UE bajo RGPD necesitaría un proyecto en la UE y el acuerdo de
tratamiento correspondiente.

**Lo que NO está resuelto**: cifrado en reposo, registro de tratamiento,
procedimiento de acceso/rectificación/supresión a pedido del titular, y política de
conservación con borrado efectivo. Ver §7.

---

## 5. Matriz de riesgo

| # | Hallazgo | Severidad | Probabilidad | Impacto | Estado |
|---|---|---|---|---|---|
| 1 | Fallo de render dejaba la ventana en blanco y se perdía el día de trabajo | Alta | Media | Alto | **Corregido** — `ErrorBoundary` en dos niveles |
| 2 | Clave de desbloqueo del cliente visible siempre, sin registro | Alta | Alta | Alto | **Corregido** — tapada por omisión + bitácora |
| 3 | Mapa de fuentes (4,97 MB) dentro del instalador | Media | Alta | Medio | **Corregido** — sólo con `BUILD_SOURCEMAP=1` |
| 4 | `deepMerge` alteraba el prototipo del objeto devuelto | Baja | Baja | Bajo | **Corregido** — claves bloqueadas |
| 4b | La copia de seguridad viajaba en claro (datos personales de clientes en un pendrive / OneDrive) | Media | Alta | Alto | **Corregido** — AES-256-GCM + PBKDF2 con frase de respaldo (§3, `docs/CIFRADO.md`) |
| 5 | Sin autenticación ni autorización reales | **Crítica** | Alta | Alto | **Abierto** — requiere servidor |
| 6 | Sin cifrado en reposo de datos personales | Alta | Media | Alto | **Abierto** — requiere servidor |
| 7 | Sin linter ni SAST automatizado | Media | Alta | Medio | **Abierto** — mitigado con `npm run security` |
| 8 | Sin CI/CD: los controles dependen de que alguien los corra | Media | Alta | Medio | **Abierto** |
| 9 | ~126 controles de formulario sin etiqueta accesible | Media | Alta | Bajo | **Abierto** — catalogado |
| 10 | Clave del equipo impresa en la etiqueta de chasis (opcional) | Media | Media | Alto | **Aceptado** — práctica de taller, configurable |

**Los hallazgos 5 y 6 son Críticos/Altos y siguen abiertos.** No se pueden cerrar en
el cliente: exigen infraestructura. Están documentados en lugar de disimulados.

---

## 6. Verificación

```bash
npm run verify      # typecheck + tests + build + escaneo + auditoría de dependencias
npm run security    # sólo el escaneo de secretos y sumideros
npm run audit:deps  # sólo dependencias
```

Resultados de la última ejecución (28/08/2026):

- `tsc --noEmit`: sin errores. Configuración estricta con `noUncheckedIndexedAccess`
  y `exactOptionalPropertyTypes`.
- `vitest run`: **661 pruebas** en 39 archivos, todas en verde. 31 son específicas de
  seguridad (`src/lib/security.test.ts`), 14 de saneamiento de entradas
  (`src/lib/sanitize.test.ts`) y 19 del cifrado de la copia
  (`src/lib/crypto.test.ts` + `src/lib/passphrase.test.ts`).
- `vite build` (escritorio) y `npm run web:build`: compilan sin código fuente.
- `npm run security`: sin hallazgos sobre 405 archivos.
- `npm audit`: 0 vulnerabilidades.

**Lo que NO se ha ejecutado**: SAST profesional, DAST, prueba de penetración externa,
escaneo de contenedores (no hay), revisión de código por un tercero.

---

## 7. Riesgos residuales y qué haría falta

### Críticos

1. **La autorización por rol es del cliente, no de la base.** El servidor separa
   talleres (nadie ve el de otro) y distingue al dueño del resto (es el único que
   invita y cambia roles). Pero `documentos` es una tabla de texto por taller: quien
   tenga la sesión de un técnico y sepa hablar HTTP puede leer el taller entero,
   incluida la caja. Dentro del taller, entonces, los roles reducen el error
   cotidiano y no contienen a alguien decidido.
   *Qué haría falta*: partir `documentos` por dominio y poner una política por rol
   sobre cada uno. Es el rediseño que está anotado en la migración, y llega el día
   que un taller con empleados lo exija de verdad.

2. **No hay cifrado en reposo, ni en el equipo ni en el servidor.** Los datos del
   taller viajan por TLS y quedan en Postgres en claro para quien administre el
   proyecto de Supabase —o sea, para nosotros—. El IMEI y la clave de desbloqueo son
   los dos campos que lo exigen antes que ninguno.
   *Qué haría falta*: cifrado del lado del cliente para esos campos, con la clave
   derivada de algo que el servidor no tenga. La cañería ya existe: es la misma de la
   copia cifrada (`docs/CIFRADO.md`).

3. **Un dispositivo perdido con la sesión abierta es el taller entero.** La sesión de
   Supabase se renueva sola y sobrevive al cierre de la aplicación; la local caduca a
   los 30 días. Hoy la única forma de cortarla es que el dueño saque a esa persona del
   taller desde Ajustes → Nube y Equipo, y eso corta el acceso a los DATOS pero no
   borra lo que ya está descargado en ese equipo.
   *Qué haría falta*: revocación de sesión desde el servidor y borrado remoto.

### Altos

4. **Sin CI/CD**, los controles de este documento dependen de que alguien recuerde
   correr `npm run verify`. El orden recomendado del pipeline: typecheck → lint →
   tests → SAST → escaneo de dependencias → escaneo de secretos → build.

5. **Sin linter.** El typechecker no cubre `react-hooks/exhaustive-deps` (cierres
   obsoletos), `no-floating-promises` ni `jsx-a11y`.
   ```
   npm i -D eslint typescript-eslint eslint-plugin-react-hooks eslint-plugin-jsx-a11y
   ```

### Aceptados conscientemente

6. **La clave del equipo puede imprimirse en la etiqueta de chasis**
   (`hardware.showPatternOnChassisLabel`). Es una práctica establecida en talleres y
   quitarla haría que se anote en un papel al lado del banco, que es peor. Queda como
   decisión del taller, con el control a la vista en Ajustes.

7. **`style-src 'unsafe-inline'`** en la CSP. React necesita estilos en línea. El
   riesgo es bajo en una aplicación sin contenido remoto y con `script-src 'self'`.

---

## 8. Respuesta a incidentes

Sin servidor, la mayoría de los incidentes son locales. Procedimiento mínimo:

| Incidente | Contener | Investigar | Recuperar |
|---|---|---|---|
| **Equipo del taller robado o comprometido** | Cambiar las claves de los servicios que ese equipo usara | La sesión caduca sola; revisar qué había en `localStorage` | Reinstalar; restaurar los ajustes desde el respaldo JSON |
| **Secreto expuesto en el repositorio** | Rotarlo de inmediato: darlo por comprometido | `npm run security` e historial de Git | Nueva credencial; nunca reutilizar la anterior |
| **Dependencia vulnerable** | `npm audit` para el alcance | Revisar si el camino vulnerable se usa | Actualizar comprobando cambios incompatibles; correr `npm run verify` |
| **Uso indebido de una clave de cliente** | Suspender el acceso de esa persona | Bitácora de la orden: quién consultó la clave y cuándo | Avisar al cliente para que la cambie |
| **Archivo malicioso cargado** | Sin ejecución posible: se re-codifica a píxeles | Revisar el álbum de la orden | Borrar la foto; queda asiento del borrado |

Después de cada incidente: documentar qué pasó, qué control faltó, y agregar la
prueba que lo habría detectado.

---

## 9. Qué NO hace esta aplicación

Dicho explícitamente para que nadie lo asuma:

- **No implementa cifrado de extremo a extremo.** Usar HTTPS no es E2EE, y este
  producto no lo necesita ni lo simula.
- **No cifra los datos en reposo** ni en `localStorage` ni en el servidor. La única
  excepción es el archivo de copia de seguridad, que sí va cifrado (§3).
- **Sí aísla un taller de otro** (RLS por membresía), y **no** aísla un rol de otro
  dentro del mismo taller: ver §7.1.
- **No revoca sesiones a distancia.** Sacar a alguien del taller le corta el acceso a
  los datos nuevos; lo que ya bajó a su equipo sigue ahí.
- **No escanea archivos con antivirus.** La defensa es la re-codificación, que es
  adecuada para imágenes y no lo sería para otros formatos.
- **No registra auditoría fuera de la orden.** La bitácora es por orden y vive en
  memoria.

---

## 10. Cómo reportar un problema de seguridad

Escribir a la dirección de contacto del taller descrita en Ajustes, con el detalle
técnico y los pasos para reproducirlo. No abrir un issue público con la información
de explotación antes de que exista una corrección.
