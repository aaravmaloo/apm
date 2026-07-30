

<div align="center">

# APM

**Un mejor gestor de contraseñas local para todos.**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go&logoColor=white)](https://golang.org)
[![Rust](https://img.shields.io/badge/Rust-stable-orange?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![License](https://img.shields.io/github/license/aaravmaloo/apm?style=flat)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-aaravmaloo.github.io%2Fapm-blue?style=flat)](https://aaravmaloo.github.io/apm)

[![CI](https://img.shields.io/github/actions/workflow/status/aaravmaloo/apm/ci.yml?branch=master&label=CI&style=flat)](https://github.com/aaravmaloo/apm/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/aaravmaloo/apm?style=flat)](https://github.com/aaravmaloo/apm/releases/latest)
[![Stars](https://img.shields.io/github/stars/aaravmaloo/apm?style=flat)](https://github.com/aaravmaloo/apm/stargazers)
[![Issues](https://img.shields.io/github/issues/aaravmaloo/apm?style=flat)](https://github.com/aaravmaloo/apm/issues)

</div>
APM es un gestor de contraseñas rápido, de conocimiento cero y basado en CLI, escrito en Go y Rust. Almacena **más de 25 tipos de secretos estructurados** en una única bóveda cifrada: desde contraseñas y códigos TOTP hasta claves SSH, expedientes médicos, fotos y archivos binarios. Este repositorio incluye dos binarios: `pm` para uso personal y `pm-team` para bóvedas compartidas en organizaciones.

---

### ¿Por qué APM?

- **Rápido y fácil de aprender** — sin memorizar comandos ni banderas. APM te solicitará lo que necesite. También hay banderas de CLI disponibles para usuarios avanzados que buscan máxima velocidad.
- **Conocimiento cero** — tu contraseña maestra nunca se almacena. Se derivan tres claves separadas de 32 bytes utilizando Argon2id. Nadie, excepto tú, puede descifrar tu bóveda.
- **Cifrado dual** — elige AES-256-GCM o XChaCha20-Poly1305. Integridad de doble capa mediante HMAC-SHA256 sobre la autenticación AEAD.
- **Portable** — un archivo de bóveda, un binario. Lleva tu bóveda a cualquier lugar.
- **Nube opcional** — sincroniza con Google Drive, GitHub o Dropbox. Completamente opt-in; no se requiere ninguna cuenta para usar APM.
- **Extensible** — un sistema de complementos basado en manifiestos con más de 100 permisos granulares, ganchos de ciclo de vida y un mercado de complementos.
- **Listo para IA** — servidor MCP nativo con tokens de ámbito limitado para que Claude, Cursor o cualquier agente compatible con MCP pueda acceder a tu bóveda de forma segura.
- **Listo para equipos** — RBAC completo, departamentos, flujos de trabajo de aprobación y bóvedas compartidas en `pm-team`.

---

### Inicio rápido

```sh
go build -o pm .
pm setup       # inicializar bóveda y elegir perfil de seguridad
pm unlock      # iniciar una sesión
pm add         # agregar un secreto (interactivo)
pm get github  # búsqueda difusa y recuperación
pm lock        # finalizar sesión
```

**Edición para equipos:**
```sh
cd team
go build -o pm-team .
```

---

### Tipos de secreto

APM admite **más de 25 tipos de secretos estructurados** con campos validados y lógica de visualización específica para cada tipo:

| # | Tipo | # | Tipo |
|---|------|---|------|
| 1 | Contraseña | 14 | Registro Docker |
| 2 | TOTP | 15 | Secreto CI/CD |
| 3 | Identificación oficial | 16 | Nota segura |
| 4 | Expediente médico | 17 | Códigos de recuperación |
| 5 | Información de viaje | 18 | Certificado |
| 6 | Contacto | 19 | Banca |
| 7 | Wi-Fi | 20 | Documento |
| 8 | Clave API | 21 | Licencia de software |
| 9 | Token | 22 | Contrato legal |
| 10 | Clave SSH | 23 | Foto |
| 11 | Configuración SSH | 24 | Audio |
| 12 | Credenciales de nube | 25 | Video |
| 13 | Kubernetes | | |

---

### Características

**Seguridad**
- Derivación de claves Argon2id de conocimiento cero: la contraseña maestra nunca se almacena
- Cifrados AEAD duales: AES-256-GCM y XChaCha20-Poly1305
- Verificación de integridad de doble capa con HMAC-SHA256
- Cuatro perfiles de seguridad ajustables: `standard`, `hardened`, `paranoid`, `legacy`
- Puntuación de confianza por secreto (0–100) basada en antigüedad, acceso y nivel de privilegios
- Registro de auditoría con evidencia de manipulación almacenado fuera de la bóveda

**Bóveda**
- Archivo único de bóveda cifrada: portable en cualquier dispositivo
- Espacios para compartimentación lógica (como carpetas)
- Búsqueda difusa con explorador interactivo y navegación por teclado
- Inspector de metadatos: fecha de creación, último acceso, contador de accesos, puntuación de confianza

**TOTP**
- Temporizadores de cuenta regresiva en vivo en una lista interactiva
- Orden personalizado persistente
- Copia directa: `pm totp github`
- Integración con daemon de autocompletado para inyectar automáticamente códigos 2FA

**Sincronización en la nube**
- Google Drive (OAuth2 PKCE), GitHub (PAT), Dropbox (OAuth2 PKCE)
- Cifrado de extremo a extremo: los proveedores nunca ven texto plano
- `.apmignore` para filtrar entradas por proveedor
- Resolución de conflictos: sobrescribir, mantener local o cancelar
- Autenticación en segundo plano

**Sesiones**
- Desbloqueo/bloqueo explícito con expiración configurable y tiempo de inactividad
- Sesiones efímeras delegadas para automatización y acceso de agentes de IA

**Servidor MCP**
- Servidor nativo de Protocolo de Contexto de Modelo
- Tokens de permisos de ámbito: `read`, `secrets`, `write`, `admin`
- Barras de seguridad para operaciones de escritura: vista previa → aprobar → recibo
- Compatible con Claude Desktop, Cursor, Windsurf y cualquier cliente MCP

**Complementos**
- Sistema de complementos basado en manifiestos
- Más de 100 permisos granulares en bóveda, red, sistema, criptografía, IU y nube
- Sistema de ganchos para eventos del ciclo de vida de la bóveda
- Mercado de complementos mediante proveedores de nube

**Autocompletado (solo Windows)**
- Autocompletado en todo el sistema sin extensión del navegador
- Atajo `Ctrl+Shift+L`, detección de contexto por título de ventana
- Inyección de pulsaciones de tecla (sin exposición del portapapeles)
- Autoinyección de TOTP para campos de 2FA

**Recuperación**
| Factor | Command |
|--------|---------|
| Email OTP | `pm auth email` |
| Recovery Key | `pm auth recover` |
| Quorum Shares (Shamir) | `pm auth quorum-setup` |
| WebAuthn Passkey | `pm auth passkey register` |
| One-time Recovery Codes | `pm auth codes generate` |

**Importar / Exportar**

| Format | Import | Export |
|--------|--------|--------|
| JSON | `pm import json` | `pm export json` |
| CSV | `pm import csv` | `pm export csv` |
| TXT | `pm import txt` | `pm export txt` |

**Motor de políticas**
```yaml
name: corporate-standard
password_policy:
  min_length: 14
  require_uppercase: true
  require_numbers: true
  require_symbols: true
rotation_policy:
  rotate_every_days: 90
  notify_before_days: 14
```
```sh
pm policy load ./policies/
```

**Edición para equipos (`pm-team`)**
- RBAC con múltiples roles
- Departamentos con dominios de cifrado aislados
- Flujos de trabajo de aprobación para entradas sensibles
- Bóvedas compartidas para compartir credenciales entre varios usuarios

---

### Perfiles de seguridad

| Perfil | Memoria Argon2 | Iteraciones | Paralelismo | Caso de uso |
|---------|--------------|------------|-------------|----------|
| `standard` | 64 MB | 3 | 2 | La mayoría de los equipos |
| `hardened` | 256 MB | 5 | 4 | Estaciones de trabajo (≥8 GB RAM) |
| `paranoid` | 512 MB | 6 | 4 | Servidores (≥16 GB RAM) |
| `legacy` | PBKDF2 | 600,000 | 1 | Compatibilidad con versiones anteriores |

APM detecta automáticamente los núcleos de tu CPU y la memoria RAM para recomendar el perfil óptimo durante `pm setup`.


### Estado de desarrollo e historial
(Esta nota es del propietario)
A partir del 30 de marzo de 2026, actualmente estoy trabajando en la GUI para APM. Al principio comenzó como una aplicación de CLI. El issue #38 lo explica todo en detalle. En general, quiero que APM llegue a un público aún más amplio. Mantendré la GUI separada en un repositorio `apm-gui` o crearé una organización y moveré ambos repositorios allí.

Comencé APM como un proyecto verdaderamente personal. Todo empezó una noche al azar, cuando quería crear mi propio gestor de contraseñas. Estaba harto de zoho password, ya que lo usaba para los TOTPs. Era increíblemente lento para funcionar, y usaba archivos de texto plano para mis tokens, lo cual no es seguro.

Por ahora, NO tengo planes de abandonar/archivar el proyecto. Permanecerá funcional durante mucho tiempo. Trato de mejorarlo cada día y lo uso a diario. A veces, el repositorio puede parecer inactivo, y eso es cuando estoy probando y experimentando con la aplicación.

---

### Estructura de lanzamientos

| Nivel | ¿Estable? | ¿Seguro para bóveda? | Propósito |
|------|---------|-------------|---------|
| Canary | ❌ | ❌ | Vista previa más temprana de funciones: puede corromper bóvedas |
| Alpha | ❌ | ✅ | Funciones inestables, integridad de la bóveda preservada |
| Beta | ✅ | ✅ | Funciones completamente probadas, despliegue cuidadoso |
| Estable | ✅ | ✅ | Lanzamientos listos para producción |

> Realiza siempre una copia de seguridad de tu bóveda antes de probar las versiones Canary.
P.D. En algunos lanzamientos, ciertos niveles pueden no publicarse dependiendo de la rapidez y facilidad para distribuirlos sin crear más niveles de los necesarios.
---

### Documentación

Documentación completa en **[aaravmaloo.github.io/apm](https://aaravmaloo.github.io/apm)**

- [Instalación](https://aaravmaloo.github.io/apm/getting-started/installation/)
- [Primeros pasos](https://aaravmaloo.github.io/apm/getting-started/first-steps/)
- [Referencia de CLI](https://aaravmaloo.github.io/apm/reference/cli/)
- [Arquitectura](https://aaravmaloo.github.io/apm/concepts/architecture/)
- [Cifrado](https://aaravmaloo.github.io/apm/concepts/encryption/)
- [Edición para equipos](https://aaravmaloo.github.io/apm/guides/team-edition/)
- [Integración MCP](https://aaravmaloo.github.io/apm/guides/mcp-integration/)
- [Contribuir](https://aaravmaloo.github.io/apm/contributing/)

---

### Contribuir

Las contribuciones son bienvenidas. Consulta [CONTRIBUTING.md](https://aaravmaloo.github.io/apm/contributing/) para las pautas.

---

### Licencia

[GPL-3.0 License](LICENSE) © Aarav Maloo
