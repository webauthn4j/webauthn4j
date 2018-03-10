-- ユーザーテーブル  --
CREATE TABLE m_user (
  id                SERIAL          NOT NULL,
  user_handle       bytea           NOT NULL,
  first_name        VARCHAR(32)    NOT NULL,
  last_name         VARCHAR(32)    NOT NULL,
  email_address     VARCHAR(64)    NOT NULL  UNIQUE,
  password          VARCHAR(64)    NOT NULL,
  locked            BOOLEAN         NOT NULL
);

-- グループテーブル  --
CREATE TABLE m_group (
  id                SERIAL          NOT NULL,
  group_name        VARCHAR(32)    NOT NULL
);

-- 権限テーブル  --
CREATE TABLE m_authority (
  id                SERIAL          NOT NULL,
  authority         VARCHAR(32)    NOT NULL
);

CREATE TABLE m_authenticator(
  id                SERIAL         NOT NULL,
  name              VARCHAR(32)    NOT NULL,
  user_id           INTEGER        NOT NULL  REFERENCES m_user(id),
  rp_id_hash bytea NOT NULL,
  counter           BIGINT         NOT NULL,
  aa_guid  bytea  NOT NULL,
  credential_id bytea NOT NULL,
  credential_public_key VARCHAR(4096) NOT NULL,
  attestation_statement  VARCHAR(4096) NOT NULL,
);

-- ユーザー・グループリレーション  --
CREATE TABLE r_user_group (
  user_id           INTEGER       NOT NULL  REFERENCES m_user(id),
  group_id          INTEGER       NOT NULL  REFERENCES m_group(id)
);

-- ユーザー・権限リレーション --
CREATE TABLE r_user_authority (
  user_id           INTEGER       NOT NULL  REFERENCES m_user(id),
  authority_id      INTEGER       NOT NULL  REFERENCES m_authority(id)
);

-- グループ・権限リレーション --
CREATE TABLE r_group_authority (
  group_id          INTEGER       NOT NULL  REFERENCES m_group(id),
  authority_id      INTEGER       NOT NULL  REFERENCES m_authority(id)
);

