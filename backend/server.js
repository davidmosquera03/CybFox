require("dotenv").config();

const express = require("express");
const swaggerUi = require("swagger-ui-express");
const mongoose = require("mongoose");

// Rutas
const assistantRoutes = require("./routes/assistantRoutes");
const testRoutes = require("./routes/testRoutes");
const urlRoutes = require("./routes/urlRoutes");
const dbRoutes = require("./routes/dbRoutes");

const app = express();
const PORT = 3000;

// Conexión Mongo
mongoose.connect(
  "mongodb://admin:password@localhost:27017/mydb?authSource=admin"
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rutas API
app.use("/assistant", assistantRoutes);
app.use("/api/db", dbRoutes);
app.use("/api", [testRoutes, urlRoutes]);

// Swagger
const swaggerFile = require("./swagger-output.json");
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerFile));

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Swagger docs: http://localhost:${PORT}/api-docs`);
});
