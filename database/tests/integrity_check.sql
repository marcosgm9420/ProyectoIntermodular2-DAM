-- =====================================================================
-- VulnFollowUp · Comprobación rápida de integridad (manual)
-- Ejecutar DESPUÉS de V1 y V2:
--   psql -U vfu_app -d vulnfollowup -f database/tests/integrity_check.sql
-- Todo va dentro de una transacción que se deshace al final:
-- la base de datos queda igual que estaba.
-- (Las pruebas automáticas definitivas serán JUnit, paso 10.)
-- =====================================================================

BEGIN;

-- Función auxiliar: ejecuta una sentencia que DEBE fallar y comprueba
-- que falla por la restricción esperada.
CREATE FUNCTION pg_temp.expect_fail(test_name TEXT, stmt TEXT, expected_constraint TEXT)
RETURNS VOID AS $$
DECLARE
    got TEXT;
BEGIN
    BEGIN
        EXECUTE stmt;
        RAISE NOTICE 'FALLO  %: se aceptó un dato que debía rechazarse', test_name;
        RETURN;
    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS got = CONSTRAINT_NAME;
        IF got = expected_constraint THEN
            RAISE NOTICE 'OK     %  (rechazado por %)', test_name, got;
        ELSE
            RAISE NOTICE 'FALLO  %: esperaba %, saltó % (%)', test_name, expected_constraint, got, SQLERRM;
        END IF;
    END;
END;
$$ LANGUAGE plpgsql;

-- Datos mínimos válidos para las pruebas
INSERT INTO asset (code, name, type, owner_id, environment)
VALUES ('AST-001', 'API de pagos', 'API', (SELECT id FROM app_user WHERE username = 'analyst1'), 'PRODUCTION');

INSERT INTO vulnerability (code, cve_id, title, description, discovered_at, created_by)
VALUES ('VFU-0001', 'CVE-2021-44228', 'Log4Shell', 'Prueba', '2026-10-02',
        (SELECT id FROM app_user WHERE username = 'analyst1'));

INSERT INTO vulnerability_asset (vulnerability_id, asset_id)
VALUES ((SELECT id FROM vulnerability WHERE code = 'VFU-0001'), (SELECT id FROM asset WHERE code = 'AST-001'));

INSERT INTO cvss_assessment (vulnerability_id, cvss_version, vector, base_score, severity, assessed_by)
VALUES ((SELECT id FROM vulnerability WHERE code = 'VFU-0001'), '3.1',
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0, 'CRITICAL',
        (SELECT id FROM app_user WHERE username = 'analyst1'));

DO $$ BEGIN RAISE NOTICE '--- Datos válidos insertados. Probando datos incorrectos ---'; END $$;

-- ---------- Coherencia CVSS (los dos ejemplos del enunciado) ----------
SELECT pg_temp.expect_fail('Versión 4.0 con vector CVSS:3.1',
  $q$INSERT INTO cvss_assessment (vulnerability_id, cvss_version, vector, base_score, severity, assessed_by, is_current)
     VALUES ((SELECT id FROM vulnerability WHERE code='VFU-0001'), '4.0',
             'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'CRITICAL', 1, false)$q$,
  'chk_cvss_vector_version');

SELECT pg_temp.expect_fail('Severidad LOW con puntuación 9.8',
  $q$INSERT INTO cvss_assessment (vulnerability_id, cvss_version, vector, base_score, severity, assessed_by, is_current)
     VALUES ((SELECT id FROM vulnerability WHERE code='VFU-0001'), '3.1',
             'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'LOW', 1, false)$q$,
  'chk_cvss_severity_score');

SELECT pg_temp.expect_fail('Puntuación fuera de rango (11.0)',
  $q$INSERT INTO cvss_assessment (vulnerability_id, cvss_version, vector, base_score, severity, assessed_by, is_current)
     VALUES ((SELECT id FROM vulnerability WHERE code='VFU-0001'), '3.1',
             'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 11.0, 'CRITICAL', 1, false)$q$,
  'chk_cvss_score_range');

SELECT pg_temp.expect_fail('Dos valoraciones vigentes a la vez',
  $q$INSERT INTO cvss_assessment (vulnerability_id, cvss_version, vector, base_score, severity, assessed_by, is_current)
     VALUES ((SELECT id FROM vulnerability WHERE code='VFU-0001'), '3.1',
             'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'CRITICAL', 1, true)$q$,
  'ux_cvss_current');

-- ---------- Vulnerabilidad ----------
SELECT pg_temp.expect_fail('Estado que no existe',
  $q$UPDATE vulnerability SET status = 'EN_CURSO', assignee_id = 1 WHERE code = 'VFU-0001'$q$,
  'chk_vuln_status');

SELECT pg_temp.expect_fail('Pasar a PENDING_REMEDIATION sin responsable',
  $q$UPDATE vulnerability SET status = 'PENDING_REMEDIATION' WHERE code = 'VFU-0001'$q$,
  'chk_vuln_assignee');

SELECT pg_temp.expect_fail('Fecha objetivo anterior al descubrimiento',
  $q$UPDATE vulnerability SET target_date = '2026-01-01' WHERE code = 'VFU-0001'$q$,
  'chk_vuln_target_date');

SELECT pg_temp.expect_fail('CVE con formato incorrecto',
  $q$UPDATE vulnerability SET cve_id = 'CVE-21-1' WHERE code = 'VFU-0001'$q$,
  'chk_vuln_cve_fmt');

SELECT pg_temp.expect_fail('Código de vulnerabilidad repetido',
  $q$INSERT INTO vulnerability (code, title, description, discovered_at, created_by)
     VALUES ('VFU-0001', 'Duplicada', 'Prueba', '2026-10-02', 1)$q$,
  'uq_vuln_code');

-- ---------- Relaciones (N:M y claves foráneas) ----------
SELECT pg_temp.expect_fail('Misma pareja vulnerabilidad-activo dos veces',
  $q$INSERT INTO vulnerability_asset (vulnerability_id, asset_id)
     VALUES ((SELECT id FROM vulnerability WHERE code='VFU-0001'), (SELECT id FROM asset WHERE code='AST-001'))$q$,
  'pk_vulnerability_asset');

SELECT pg_temp.expect_fail('Vincular a un activo que no existe',
  $q$INSERT INTO vulnerability_asset (vulnerability_id, asset_id)
     VALUES ((SELECT id FROM vulnerability WHERE code='VFU-0001'), 999999)$q$,
  'fk_va_asset');

SELECT pg_temp.expect_fail('Borrar un activo con vulnerabilidades',
  $q$DELETE FROM asset WHERE code = 'AST-001'$q$,
  'fk_va_asset');

SELECT pg_temp.expect_fail('Borrar un usuario responsable de un activo',
  $q$DELETE FROM app_user WHERE username = 'analyst1'$q$,
  'fk_asset_owner');

-- ---------- Activos y proveedores ----------
SELECT pg_temp.expect_fail('Entorno de activo no válido',
  $q$INSERT INTO asset (code, name, type, owner_id, environment) VALUES ('AST-002', 'X', 'API', 1, 'PROD')$q$,
  'chk_asset_env');

SELECT pg_temp.expect_fail('Contrato que acaba antes de empezar',
  $q$INSERT INTO ict_provider (code, name, service_provided, criticality, contract_ref, contract_start,
                               contract_end, next_review_date, contact_name, contact_email)
     VALUES ('PRV-001', 'HostingSur S.L.', 'Hosting', 'HIGH', 'CT-1', '2026-01-01', '2025-01-01',
             '2027-01-01', 'Contacto', 'c@x.example')$q$,
  'chk_provider_contract');

SELECT pg_temp.expect_fail('Rol que no existe',
  $q$INSERT INTO role (name) VALUES ('SUPERADMIN')$q$,
  'chk_role_name');

DO $$ BEGIN RAISE NOTICE '--- Fin de las pruebas: se deshacen todos los cambios ---'; END $$;

ROLLBACK;
