-- =====================================================================
-- VulnFollowUp · V2__seed_users.sql
-- Carga inicial fija: roles y usuarios de prueba (CU1)
--
-- Contraseña de TODOS los usuarios de demo: Demo1234!
-- Es una contraseña SOLO de demostración. Se guarda como hash BCrypt
-- ($2a$, coste 10), que Spring Security (BCryptPasswordEncoder) acepta.
-- Los activos, proveedores y vulnerabilidades NO van aquí: se cargan
-- desde los ficheros JSON de data/ al arrancar (CU1).
-- =====================================================================

INSERT INTO role (name) VALUES
    ('ADMIN'),
    ('ANALYST'),
    ('VIEWER');

INSERT INTO app_user (username, password_hash, full_name, email, role_id) VALUES
    ('admin',    '$2a$10$BenyYh4D.McGaxhnJcqQ1Os9m9RcgOOWm3i.XZxq6Q0EASdbX6Rte', 'Administrador Demo', 'admin@vulnfollowup.example',
        (SELECT id FROM role WHERE name = 'ADMIN')),
    ('analyst1', '$2a$10$BenyYh4D.McGaxhnJcqQ1Os9m9RcgOOWm3i.XZxq6Q0EASdbX6Rte', 'Analista Uno',       'analyst1@vulnfollowup.example',
        (SELECT id FROM role WHERE name = 'ANALYST')),
    ('analyst2', '$2a$10$BenyYh4D.McGaxhnJcqQ1Os9m9RcgOOWm3i.XZxq6Q0EASdbX6Rte', 'Analista Dos',       'analyst2@vulnfollowup.example',
        (SELECT id FROM role WHERE name = 'ANALYST')),
    ('viewer',   '$2a$10$BenyYh4D.McGaxhnJcqQ1Os9m9RcgOOWm3i.XZxq6Q0EASdbX6Rte', 'Cliente Consulta',   'viewer@vulnfollowup.example',
        (SELECT id FROM role WHERE name = 'VIEWER'));
