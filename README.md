# CybFox

Extension web para brindar seguridad a la navegación en linea de manera pedagogica y clara.

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