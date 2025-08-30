const { defineConfig } = require("cypress");

module.exports = defineConfig({
  projectId: "vs8ft4", // tu projectId
  e2e: {
    setupNodeEvents(on, config) {
      // acá podés agregar listeners, tasks, etc.
      // Ejemplo: imprimir un mensaje al iniciar los tests
      on('before:run', () => {
        console.log('🚀 Iniciando pruebas E2E con Cypress');
      });

      return config; // importante devolver la config
    },

    // Rutas y opciones básicas para tu proyecto
    baseUrl: "http://localhost:3000", // cambia al puerto donde corre tu app
    specPattern: "cypress/e2e/**/*.cy.{js,jsx,ts,tsx}", // ubicación de tus tests
    supportFile: "cypress/support/e2e.js", // archivo de soporte global
    screenshotsFolder: "cypress/screenshots",
    videosFolder: "cypress/videos",
    video: true, // graba videos de ejecución (útil para Dashboard)
  },
});
