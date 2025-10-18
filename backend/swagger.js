const swaggerAutogen = require("swagger-autogen")();

const doc = {
  info: {
    title: "My Express API",
    description: "Auto-generated API documentation",
    version: "1.0.0",
  },
  host: "localhost:3000",
  schemes: ["http"],
};

const outputFile = "./swagger-output.json"; // file to be generated
const endpointsFiles = ["./server.js"]; // or your main app file

swaggerAutogen(outputFile, endpointsFiles, doc);
