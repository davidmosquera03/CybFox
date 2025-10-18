require("dotenv").config();
const express = require("express");
const swaggerUi = require("swagger-ui-express");
const app = express();
const PORT = 3000;

const testRoutes = require("./routes/testRoutes");
const urlRoutes = require("./routes/urlRoutes");

app.use("/api", [testRoutes, urlRoutes]);

const swaggerFile = require("./swagger-output.json");
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerFile));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Swagger docs at: http://localhost:${PORT}/api-docs`);
});
