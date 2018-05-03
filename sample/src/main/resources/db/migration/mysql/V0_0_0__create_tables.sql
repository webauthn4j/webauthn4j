-- User table  --
CREATE TABLE m_user (
  id                INTEGER        NOT NULL AUTO_INCREMENT,
  user_handle       BLOB            NOT NULL,
  first_name        VARCHAR(32)    NOT NULL,
  last_name         VARCHAR(32)    NOT NULL,
  email_address     VARCHAR(64)    NOT NULL  UNIQUE,
  password          VARCHAR(64)    NOT NULL,
  pwauth_allowed    BOOLEAN         NOT NULL,
  locked            BOOLEAN         NOT NULL,
  primary key(id)
);

-- Group table  --
CREATE TABLE m_group (
  id                INTEGER        NOT NULL AUTO_INCREMENT,
  group_name        VARCHAR(32)    NOT NULL,
  primary key(id)
);

-- Authority table  --
CREATE TABLE m_authority (
  id                INTEGER        NOT NULL AUTO_INCREMENT,
  authority         VARCHAR(32)    NOT NULL,
  primary key(id)
);

-- Authenticator table  --
CREATE TABLE m_authenticator(
  id                     INTEGER       NOT NULL AUTO_INCREMENT,
  name                   VARCHAR(32)   NOT NULL,
  user_id                INTEGER       NOT NULL  REFERENCES m_user(id),
  rp_id_hash             BLOB           NOT NULL,
  counter                BIGINT         NOT NULL,
  aa_guid                BLOB           NOT NULL,
  credential_id          BLOB           NOT NULL,
  credential_public_key  VARCHAR(4096) NOT NULL,
  attestation_statement  VARCHAR(4096) NOT NULL,
  primary key(id)
);


-- ユーザー・グループリレーション  --
CREATE TABLE r_user_group (
  user_id           INTEGER        NOT NULL,
  group_id          INTEGER        NOT NULL,
  FOREIGN KEY (user_id) REFERENCES m_user(id) ON DELETE CASCADE,
  FOREIGN KEY (group_id) REFERENCES m_group(id) ON DELETE CASCADE
);

-- ユーザー・権限リレーション --
CREATE TABLE r_user_authority (
  user_id           INTEGER        NOT NULL,
  authority_id      INTEGER        NOT NULL,
  FOREIGN KEY (user_id) REFERENCES m_user(id) ON DELETE CASCADE,
  FOREIGN KEY (authority_id) REFERENCES m_authority(id) ON DELETE CASCADE
);

-- グループ・権限リレーション --
CREATE TABLE r_group_authority (
  group_id           INTEGER        NOT NULL,
  authority_id       INTEGER        NOT NULL,
  FOREIGN KEY (group_id) REFERENCES m_group(id) ON DELETE CASCADE,
  FOREIGN KEY (authority_id) REFERENCES m_authority(id) ON DELETE CASCADE
);

