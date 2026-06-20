-- Monster Fitness — init.sql
-- Executado automaticamente na primeira inicialização do container MySQL

SET NAMES utf8mb4;

-- Tabela de usuários
CREATE TABLE IF NOT EXISTS usuarios (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    nome          VARCHAR(120)  NOT NULL,
    email         VARCHAR(180)  NOT NULL UNIQUE,
    cpf           VARCHAR(14)   NOT NULL UNIQUE,
    nascimento    DATE,
    telefone      VARCHAR(20),
    senha_hash    VARCHAR(255)  NOT NULL,
    plano         ENUM('mensal','trimestral','semestral','anual','premium') NOT NULL DEFAULT 'mensal',
    objetivo      VARCHAR(30),
    nivel         VARCHAR(20),
    ativo         TINYINT(1)    NOT NULL DEFAULT 1,
    criado_em     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizado_em DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_ativo (ativo)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela de sessões JWT
CREATE TABLE IF NOT EXISTS sessoes (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id  INT         NOT NULL,
    jti         VARCHAR(64) NOT NULL UNIQUE,
    criado_em   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expira_em   DATETIME    NOT NULL,
    revogado    TINYINT(1)  NOT NULL DEFAULT 0,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    INDEX idx_jti (jti),
    INDEX idx_revogado (revogado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabela de tokens CSRF
CREATE TABLE IF NOT EXISTS csrf_tokens (
    token       VARCHAR(64) PRIMARY KEY,
    criado_em   DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    usado       TINYINT(1)  NOT NULL DEFAULT 0,
    INDEX idx_criado (criado_em)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Evento de limpeza automática (expira sessões e csrf tokens velhos)
CREATE EVENT IF NOT EXISTS limpeza_sessoes
    ON SCHEDULE EVERY 1 HOUR
    DO
    BEGIN
        DELETE FROM sessoes     WHERE expira_em < NOW();
        DELETE FROM csrf_tokens WHERE criado_em < NOW() - INTERVAL 2 HOUR;
    END;
