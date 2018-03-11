-- ユーザーテーブル  --
CREATE TABLE m_user (
  id                INTEGER        NOT NULL AUTO_INCREMENT,
  first_name        VARCHAR(32)    NOT NULL,
  last_name         VARCHAR(32)    NOT NULL,
  email_address     VARCHAR(64)    NOT NULL  UNIQUE,
  password          VARCHAR(64)    NOT NULL,
  pwauth_allowed    BOOLEAN         NOT NULL,
  locked            BOOLEAN         NOT NULL,
  primary key(id)
);

-- グループテーブル  --
CREATE TABLE m_group (
  id                INTEGER        NOT NULL AUTO_INCREMENT,
  group_name        VARCHAR(32)    NOT NULL,
  primary key(id)
);

-- 権限テーブル  --
CREATE TABLE m_authority (
  id                INTEGER        NOT NULL AUTO_INCREMENT,
  authority         VARCHAR(32)    NOT NULL,
  primary key(id)
);

-- ユーザー・グループリレーション  --
CREATE TABLE r_user_group (
  user_id           INTEGER        NOT NULL,
  group_id          INTEGER        NOT NULL,
  FOREIGN KEY (user_id) REFERENCES m_user(id),
  FOREIGN KEY (group_id) REFERENCES m_group(id)
);

-- ユーザー・権限リレーション --
CREATE TABLE r_user_authority (
  user_id           INTEGER        NOT NULL,
  authority_id      INTEGER        NOT NULL,
  FOREIGN KEY (user_id) REFERENCES m_user(id),
  FOREIGN KEY (authority_id) REFERENCES m_authority(id)
);

-- グループ・権限リレーション --
CREATE TABLE r_group_authority (
  group_id           INTEGER        NOT NULL,
  authority_id       INTEGER        NOT NULL,
  FOREIGN KEY (group_id) REFERENCES m_group(id),
  FOREIGN KEY (authority_id) REFERENCES m_authority(id)
);

