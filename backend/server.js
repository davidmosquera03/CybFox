require("dotenv").config();
const express = require("express");
const swaggerUi = require("swagger-ui-express");

const mongoose = require("mongoose");

// Connect to MongoDB
mongoose.connect(
  "mongodb://admin:password@localhost:27017/mydb?authSource=admin"
);

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const testRoutes = require("./routes/testRoutes");
const urlRoutes = require("./routes/urlRoutes");

app.use("/api", [testRoutes, urlRoutes]);

const swaggerFile = require("./swagger-output.json");

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerFile));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Swagger docs at: http://localhost:${PORT}/api-docs`);
});
