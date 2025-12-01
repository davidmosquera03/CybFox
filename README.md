
# CybFox
## 📄 Derechos de Autor y Licencia

**CybFox – Agente de software con asistente virtual para análisis de riesgo, verificación de autenticidad web y detección de actividades fraudulentas.**

**Autores:**
- David Hernández Mosquera  
- Luisa Fernanda Guzmán Santoya  
- María Isabel Solá Valle  

Este proyecto está licenciado bajo la **GNU General Public License v3.0 (GPL-3.0)**.  
Esto significa que el código puede ser utilizado, estudiado, modificado y distribuido,
siempre y cuando cualquier versión derivada se mantenga bajo la misma licencia
y se preserve el reconocimiento de los autores.

El software se proporciona **sin garantía alguna**, incluyendo sin limitación
la garantía implícita de comerciabilidad o adecuación para un propósito particular.
Para más detalles, consulte el archivo [`LICENSE`](./LICENSE) incluido en este repositorio
o visite: https://www.gnu.org/licenses/gpl-3.0.html


## Contenido

1. Backend (Express JS)

2. Extension Web

## Ejecución

### Base de datos

```
cd backend
docker compose up -d
```

### Backend

```
cd backend
npm i
node server.js
```

Si se hacen alteraciones a rutas:

```
node swagger.js && node server.js
```

### Frontend

```
cd extension.security
cd frontend
npm i
npm run build
```

### Extension

En Chrome ir a "chrome://extensions/", activar modo desarrollador

Hacer clic en "load unpacked"

seleccionar extension.security


npm install marked
