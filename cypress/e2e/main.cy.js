describe('Favoritos', () => {
  it('Películas o series favoritas por el usuario', () => {
    cy.request('POST', 'http://localhost:3001/login', {
      username: 'user',
      password: 'user'
    }).then((response) => {
      expect(response.body.ok).to.be.true;
      window.localStorage.setItem('jwt', response.body.token);
      window.localStorage.setItem('loggedInUser', JSON.stringify(response.body.user));
      cy.visit('/favoritos.html');
      cy.get('.card-title').should('exist');
    });
  });
  it('Favoritos del usuario vacíos.', () => {
    cy.request('POST', 'http://localhost:3001/login', {
      username: 'adminnnnn',
      password: 'Admin123@@'
    }).then((response) => {
      expect(response.body.ok).to.be.true;
      window.localStorage.setItem('jwt', response.body.token);
      window.localStorage.setItem('loggedInUser', JSON.stringify(response.body.user));
      cy.visit('/favoritos.html');
      cy.get('body').then($body => {
        if ($body.find('.favorito-item').length) {
          cy.get('.favorito-item').should('exist');
        } else {
          cy.contains('No tienes favoritos.').should('be.visible');
        }
      });
    });
  });
});
/// Prueba de login

describe('Login de usuario', () => {
  it('Debe mostrar error con credenciales incorrectas', () => {
  cy.visit('/login');
    cy.get('input[name="username"]').type('sigma');
    cy.get('input[name="password"]').type('boyyyyy');
    cy.get('button[type="submit"]').click();
    cy.contains('Usuario o contraseña incorrectos').should('be.visible');
  });

  it('Debe permitir login con credenciales válidas', () => {
  cy.visit('/login');
    cy.get('input[name="username"]').type('adminnnnn');
    cy.get('input[name="password"]').type('Admin123@@');
    cy.get('button[type="submit"]').click();
  cy.url().should('include', '/dash');
  });
});

/// Prueba de registro

describe('Registro de usuario', () => {
  it('Debe mostrar error si faltan datos', () => {
  cy.visit('/register');
  cy.get('input[name="username"]').clear();
  cy.get('input[name="email"]').clear();
  cy.get('input[name="password"]').clear();
    cy.get('button[type="submit"]').click();
    cy.contains('Por favor, completa todos los campos.').should('be.visible');
  });
});


describe('Guardados', () => {
  it('Películas o series guardadas por el usuario', () => {
    cy.request('POST', 'http://localhost:3001/login', {
      username: 'user',
      password: 'user'
    }).then((response) => {
      expect(response.body.ok).to.be.true;
      window.localStorage.setItem('jwt', response.body.token);
      window.localStorage.setItem('loggedInUser', JSON.stringify(response.body.user));
      cy.visit('/guardados.html');
      cy.get('.card-title').should('exist');
    });
  });
  it('Guardados del usuario vacíos.', () => {
    cy.request('POST', 'http://localhost:3001/login', {
      username: 'adminnnnn',
      password: 'Admin123@@'
    }).then((response) => {
      expect(response.body.ok).to.be.true;
  window.localStorage.setItem('jwt', response.body.token);
  window.localStorage.setItem('loggedInUser', JSON.stringify(response.body.user));
      cy.visit('/guardados.html');
      cy.get('body').then($body => {
        if ($body.find('.guardado-item').length) {
          cy.get('.guardado-item').should('exist');
        } else {
          cy.contains('No tienes títulos guardados para ver más tarde.').should('be.visible');
        }
      });
    });
  });
});

  it('Debe redirigir a 404 si usuario no es admin en /admin.html', () => {
    cy.request('POST', 'http://localhost:3001/login', {
      username: 'user',
      password: 'user'
    }).then((response) => {
      expect(response.body.ok).to.be.true;
      window.localStorage.setItem('userToken', response.body.token);
      cy.visit('/admin.html');
  cy.url().should('include', '/404');
      cy.contains('404 - Acceso Denegado').should('be.visible');
    });
  });
