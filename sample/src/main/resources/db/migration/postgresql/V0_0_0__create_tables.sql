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

