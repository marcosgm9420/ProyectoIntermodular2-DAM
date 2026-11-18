-- =====================================================================
-- VulnFollowUp · V1__schema.sql
-- Creación del esquema de la base de datos (PostgreSQL 16)
-- Módulo: Acceso a Datos + Sistemas de Gestión Empresarial (Parte 1)
--
-- Orden de creación: primero las tablas que no dependen de nadie
-- (role), después las que apuntan a ellas con claves foráneas.
-- Todas las restricciones tienen nombre para que los errores
-- se entiendan (p. ej. "chk_cvss_severity_score").
-- =====================================================================


-- =====================================================================
-- 1. USUARIOS Y ROLES
-- =====================================================================

CREATE TABLE role (
    id    SMALLSERIAL  PRIMARY KEY,
    name  VARCHAR(20)  NOT NULL,
    CONSTRAINT uq_role_name  UNIQUE (name),
    CONSTRAINT chk_role_name CHECK (name IN ('ADMIN', 'ANALYST', 'VIEWER'))
);

CREATE TABLE app_user (
    id             BIGSERIAL     PRIMARY KEY,
    username       VARCHAR(50)   NOT NULL,
    password_hash  VARCHAR(100)  NOT NULL,          -- BCrypt, nunca texto plano
    full_name      VARCHAR(100)  NOT NULL,
    email          VARCHAR(120),
    role_id        SMALLINT      NOT NULL,
    active         BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMP     NOT NULL DEFAULT now(),
    CONSTRAINT uq_user_username UNIQUE (username),
    CONSTRAINT uq_user_email    UNIQUE (email),
    CONSTRAINT fk_user_role     FOREIGN KEY (role_id) REFERENCES role (id)
);


-- =====================================================================
-- 2. ACTIVOS Y PROVEEDORES TIC (SGE)
-- =====================================================================

CREATE TABLE asset (
    id           BIGSERIAL     PRIMARY KEY,
    code         VARCHAR(20)   NOT NULL,            -- AST-001
    name         VARCHAR(120)  NOT NULL,
    type         VARCHAR(20)   NOT NULL,
    owner_id     BIGINT        NOT NULL,            -- responsable del activo
    environment  VARCHAR(15)   NOT NULL,
    status       VARCHAR(10)   NOT NULL DEFAULT 'ACTIVE',
    created_at   TIMESTAMP     NOT NULL DEFAULT now(),
    updated_at   TIMESTAMP     NOT NULL DEFAULT now(),
    CONSTRAINT uq_asset_code        UNIQUE (code),
    CONSTRAINT fk_asset_owner       FOREIGN KEY (owner_id) REFERENCES app_user (id),
    CONSTRAINT chk_asset_type       CHECK (type IN ('API', 'SERVER', 'DATABASE', 'APPLICATION', 'NETWORK', 'OTHER')),
    CONSTRAINT chk_asset_env        CHECK (environment IN ('PRODUCTION', 'STAGING', 'DEVELOPMENT')),
    CONSTRAINT chk_asset_status     CHECK (status IN ('ACTIVE', 'INACTIVE')),
    CONSTRAINT chk_asset_code_fmt   CHECK (code ~ '^AST-[0-9]{3,}$')
);

CREATE TABLE ict_provider (
    id                BIGSERIAL     PRIMARY KEY,
    code              VARCHAR(20)   NOT NULL,       -- PRV-001
    name              VARCHAR(120)  NOT NULL,
    service_provided  VARCHAR(200)  NOT NULL,
    criticality       VARCHAR(10)   NOT NULL,
    contract_ref      VARCHAR(50)   NOT NULL,
    contract_start    DATE          NOT NULL,
    contract_end      DATE,                         -- NULL = indefinido
    next_review_date  DATE          NOT NULL,
    contact_name      VARCHAR(100)  NOT NULL,
    contact_email     VARCHAR(120)  NOT NULL,
    active            BOOLEAN       NOT NULL DEFAULT TRUE,
    CONSTRAINT uq_provider_code         UNIQUE (code),
    CONSTRAINT uq_provider_name         UNIQUE (name),
    CONSTRAINT chk_provider_criticality CHECK (criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT chk_provider_contract    CHECK (contract_end IS NULL OR contract_end >= contract_start),
    CONSTRAINT chk_provider_code_fmt    CHECK (code ~ '^PRV-[0-9]{3,}$')
);

-- Relación N:M proveedor <-> activo
CREATE TABLE provider_asset (
    provider_id  BIGINT  NOT NULL,
    asset_id     BIGINT  NOT NULL,
    CONSTRAINT pk_provider_asset          PRIMARY KEY (provider_id, asset_id),
    CONSTRAINT fk_provider_asset_provider FOREIGN KEY (provider_id) REFERENCES ict_provider (id) ON DELETE CASCADE,
    CONSTRAINT fk_provider_asset_asset    FOREIGN KEY (asset_id)    REFERENCES asset (id)        ON DELETE CASCADE
);


-- =====================================================================
-- 3. VULNERABILIDADES
-- =====================================================================

CREATE TABLE vulnerability (
    id             BIGSERIAL     PRIMARY KEY,
    code           VARCHAR(20)   NOT NULL,          -- VFU-0001 (identificador interno)
    cve_id         VARCHAR(20),                     -- CVE-2021-44228 (opcional)
    title          VARCHAR(200)  NOT NULL,
    description    TEXT          NOT NULL,
    discovered_at  DATE          NOT NULL,
    status         VARCHAR(25)   NOT NULL DEFAULT 'OPEN',
    assignee_id    BIGINT,                          -- responsable de la remediación
    target_date    DATE,                            -- fecha objetivo de remediación
    created_by     BIGINT        NOT NULL,
    created_at     TIMESTAMP     NOT NULL DEFAULT now(),
    updated_at     TIMESTAMP     NOT NULL DEFAULT now(),
    version        BIGINT        NOT NULL DEFAULT 0, -- bloqueo optimista (@Version, Parte 2)
    CONSTRAINT uq_vuln_code          UNIQUE (code),
    CONSTRAINT uq_vuln_cve           UNIQUE (cve_id),
    CONSTRAINT fk_vuln_assignee      FOREIGN KEY (assignee_id) REFERENCES app_user (id),
    CONSTRAINT fk_vuln_created_by    FOREIGN KEY (created_by)  REFERENCES app_user (id),
    CONSTRAINT chk_vuln_status       CHECK (status IN ('OPEN', 'PENDING_REMEDIATION', 'RESOLVED', 'CLOSED')),
    CONSTRAINT chk_vuln_code_fmt     CHECK (code ~ '^VFU-[0-9]{4,}$'),
    CONSTRAINT chk_vuln_cve_fmt      CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    CONSTRAINT chk_vuln_target_date  CHECK (target_date IS NULL OR target_date >= discovered_at),
    -- Si ya no está ABIERTA, alguien tiene que ser responsable de remediarla
    CONSTRAINT chk_vuln_assignee     CHECK (status = 'OPEN' OR assignee_id IS NOT NULL)
);

-- Relación N:M vulnerabilidad <-> activo (obligatoria en el enunciado)
CREATE TABLE vulnerability_asset (
    vulnerability_id  BIGINT  NOT NULL,
    asset_id          BIGINT  NOT NULL,
    CONSTRAINT pk_vulnerability_asset PRIMARY KEY (vulnerability_id, asset_id),
    CONSTRAINT fk_va_vulnerability    FOREIGN KEY (vulnerability_id) REFERENCES vulnerability (id) ON DELETE CASCADE,
    -- Sin CASCADE: un activo afectado no se borra, se desactiva (status = 'INACTIVE')
    CONSTRAINT fk_va_asset            FOREIGN KEY (asset_id)         REFERENCES asset (id)
);

CREATE TABLE vulnerability_reference (
    id                BIGSERIAL     PRIMARY KEY,
    vulnerability_id  BIGINT        NOT NULL,
    url               VARCHAR(500)  NOT NULL,
    source            VARCHAR(50),                  -- NVD, CVE.org, fabricante...
    CONSTRAINT fk_ref_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES vulnerability (id) ON DELETE CASCADE,
    CONSTRAINT uq_ref_url           UNIQUE (vulnerability_id, url),
    CONSTRAINT chk_ref_url          CHECK (url ~ '^https?://')
);

CREATE TABLE cvss_assessment (
    id                BIGSERIAL     PRIMARY KEY,
    vulnerability_id  BIGINT        NOT NULL,
    cvss_version      VARCHAR(3)    NOT NULL,
    vector            VARCHAR(200)  NOT NULL,
    base_score        NUMERIC(3,1)  NOT NULL,
    severity          VARCHAR(10)   NOT NULL,
    assessed_at       TIMESTAMP     NOT NULL DEFAULT now(),
    assessed_by       BIGINT        NOT NULL,
    is_current        BOOLEAN       NOT NULL DEFAULT TRUE,
    CONSTRAINT fk_cvss_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES vulnerability (id) ON DELETE CASCADE,
    CONSTRAINT fk_cvss_assessed_by   FOREIGN KEY (assessed_by)      REFERENCES app_user (id),
    CONSTRAINT chk_cvss_version      CHECK (cvss_version IN ('3.1', '4.0')),
    CONSTRAINT chk_cvss_score_range  CHECK (base_score BETWEEN 0.0 AND 10.0),
    CONSTRAINT chk_cvss_severity     CHECK (severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    -- El vector tiene que empezar por la versión declarada: 'CVSS:3.1/...' o 'CVSS:4.0/...'
    CONSTRAINT chk_cvss_vector_version CHECK (vector LIKE 'CVSS:' || cvss_version || '/%'),
    -- La severidad tiene que corresponder a la escala cualitativa de la puntuación
    CONSTRAINT chk_cvss_severity_score CHECK (severity = CASE
        WHEN base_score = 0.0 THEN 'NONE'
        WHEN base_score < 4.0 THEN 'LOW'
        WHEN base_score < 7.0 THEN 'MEDIUM'
        WHEN base_score < 9.0 THEN 'HIGH'
        ELSE 'CRITICAL'
    END)
);

-- Solo UNA valoración vigente por vulnerabilidad; las anteriores quedan como histórico
CREATE UNIQUE INDEX ux_cvss_current ON cvss_assessment (vulnerability_id) WHERE is_current;

-- Comentarios, evidencias y cambios de estado (ciclo de remediación, CU4)
CREATE TABLE remediation_comment (
    id                BIGSERIAL    PRIMARY KEY,
    vulnerability_id  BIGINT       NOT NULL,
    author_id         BIGINT       NOT NULL,
    comment           TEXT         NOT NULL,
    evidence          TEXT,
    status_from       VARCHAR(25),
    status_to         VARCHAR(25),
    created_at        TIMESTAMP    NOT NULL DEFAULT now(),
    CONSTRAINT fk_comment_vulnerability FOREIGN KEY (vulnerability_id) REFERENCES vulnerability (id) ON DELETE CASCADE,
    CONSTRAINT fk_comment_author        FOREIGN KEY (author_id)        REFERENCES app_user (id),
    CONSTRAINT chk_comment_status_from  CHECK (status_from IN ('OPEN', 'PENDING_REMEDIATION', 'RESOLVED', 'CLOSED')),
    CONSTRAINT chk_comment_status_to    CHECK (status_to   IN ('OPEN', 'PENDING_REMEDIATION', 'RESOLVED', 'CLOSED')),
    -- O se informan los dos estados (hubo cambio) o ninguno (solo comentario)
    CONSTRAINT chk_comment_status_pair  CHECK ((status_from IS NULL) = (status_to IS NULL))
);


-- =====================================================================
-- 4. TRAZABILIDAD
-- =====================================================================

CREATE TABLE audit_log (
    id           BIGSERIAL    PRIMARY KEY,
    user_id      BIGINT,                            -- NULL = proceso del sistema
    action       VARCHAR(20)  NOT NULL,
    entity_type  VARCHAR(30)  NOT NULL,             -- 'vulnerability', 'asset', 'ict_provider'...
    entity_id    BIGINT,
    old_value    JSONB,
    new_value    JSONB,
    created_at   TIMESTAMP    NOT NULL DEFAULT now(),
    CONSTRAINT fk_audit_user    FOREIGN KEY (user_id) REFERENCES app_user (id),
    CONSTRAINT chk_audit_action CHECK (action IN ('CREATE', 'UPDATE', 'DELETE', 'STATUS_CHANGE', 'IMPORT', 'LOGIN'))
);

CREATE TABLE import_job (
    id                BIGSERIAL     PRIMARY KEY,
    file_name         VARCHAR(200)  NOT NULL,
    launched_by       BIGINT,
    started_at        TIMESTAMP     NOT NULL DEFAULT now(),
    finished_at       TIMESTAMP,
    status            VARCHAR(10)   NOT NULL DEFAULT 'RUNNING',
    total_records     INT,
    imported_records  INT           NOT NULL DEFAULT 0,
    error_count       INT           NOT NULL DEFAULT 0,
    error_report      TEXT,                         -- JSON con los errores de cada registro
    CONSTRAINT fk_import_user     FOREIGN KEY (launched_by) REFERENCES app_user (id),
    CONSTRAINT chk_import_status  CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
    CONSTRAINT chk_import_counts  CHECK (imported_records >= 0 AND error_count >= 0)
);


-- =====================================================================
-- 5. VISTA E ÍNDICES PARA FILTROS Y DASHBOARD
-- =====================================================================

-- Cada vulnerabilidad con su valoración CVSS vigente (la usan filtros y dashboard)
CREATE VIEW v_vulnerability_current AS
SELECT v.id, v.code, v.cve_id, v.title, v.description, v.discovered_at,
       v.status, v.assignee_id, v.target_date, v.created_by,
       v.created_at, v.updated_at, v.version,
       c.cvss_version, c.vector, c.base_score, c.severity, c.assessed_at
FROM vulnerability v
LEFT JOIN cvss_assessment c
       ON c.vulnerability_id = v.id
      AND c.is_current;

CREATE INDEX ix_vuln_status    ON vulnerability (status);
CREATE INDEX ix_vuln_assignee  ON vulnerability (assignee_id);
CREATE INDEX ix_cvss_severity  ON cvss_assessment (severity)   WHERE is_current;
CREATE INDEX ix_cvss_score     ON cvss_assessment (base_score) WHERE is_current;
CREATE INDEX ix_va_asset       ON vulnerability_asset (asset_id);
CREATE INDEX ix_pa_asset       ON provider_asset (asset_id);
CREATE INDEX ix_audit_entity   ON audit_log (entity_type, entity_id);
