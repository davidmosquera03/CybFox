const swaggerAutogen = require("swagger-autogen")();

const doc = {
  info: {
    title: "CybFox",
    description: "Security extension backend",
    version: "1.0.0",
  },
  tags: [
    { name: "Tests", description: "Test endpoints" },
    { name: "URLs", description: "URL analysis endpoints" },
  ],
  host: "localhost:3000",
  schemes: ["http"],
};

const outputFile = "./swagger-output.json";
const endpointsFiles = ["./server.js"];

swaggerAutogen(outputFile, endpointsFiles, doc);
