# UruArregla — Descargas

Instaladores oficiales de **UruArregla**, el sistema de gestión para
talleres de service técnico.

- Sitio: https://uruarregla.vercel.app
- Aplicación web: https://uruarregla-app.vercel.app
- Descargas: https://uruarregla.vercel.app/descargas

Este repositorio sólo publica las versiones. El código es privado.

## Cómo se instala

Bajá `UruArregla-Windows-x64-setup.exe` de la última publicación
([Releases](../../releases/latest)) y ejecutalo. Quien ya tiene
UruArregla instalado no necesita bajar nada: la aplicación avisa sola
cuando hay una versión nueva y se actualiza desde **Ajustes → Sistema**.

Para comprobar que la descarga llegó entera, comparala con
`SHA256SUMS.txt`:

```powershell
Get-FileHash .\UruArregla-Windows-x64-setup.exe -Algorithm SHA256
```

## Contacto

Ventas y soporte: WhatsApp 099 681 250 · contacto@gsweb.com.uy
(lunes a viernes de 10 a 17 h). Para reportar un problema de
seguridad, ver [SECURITY.md](SECURITY.md).
