INSERT INTO m_user VALUES (1, '', 'Ichiro', 'Tanaka', 'i.tanaka@example.com', '$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq', false);
INSERT INTO m_user VALUES (2, '', 'Jiro',   'Yamada', 'j.yamada@example.com', '$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq', false);
INSERT INTO m_user VALUES (3, '', 'Saburo',   'Takahashi', 's.takahashi@example.com', '$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq', false);

INSERT INTO m_group VALUES (1, 'グループA');
INSERT INTO m_group VALUES (2, 'グループB');
INSERT INTO m_group VALUES (3, 'グループC');

INSERT INTO m_authority VALUES (1, 'ROLE_ADMIN');
INSERT INTO m_authority VALUES (2, 'ROLE_ACTUATOR');

INSERT INTO r_user_group VALUES (1, 1);
INSERT INTO r_user_group VALUES (2, 1);
INSERT INTO r_user_group VALUES (1, 2);

INSERT INTO r_user_authority VALUES (1, 1);
INSERT INTO r_user_authority VALUES (1, 2);

INSERT INTO r_group_authority VALUES (1, 1);

COMMIT;