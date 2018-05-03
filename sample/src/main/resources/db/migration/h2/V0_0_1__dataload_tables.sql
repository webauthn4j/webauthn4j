INSERT INTO m_user VALUES (1, '5F0595F889784ABB8220C6736727E8BE', 'Ichiro', 'Tanaka', 'i.tanaka@example.com', '$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq', true, false); /* password: "password" */
INSERT INTO m_user VALUES (2, '6FC60DE8FE5044118803672F93CA1815', 'Jiro',   'Yamada', 'j.yamada@example.com', '$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq', true, false); /* password: "password" */
INSERT INTO m_user VALUES (3, 'B05360907F6040A0914AF9F5FE38C120', 'Saburo',   'Takahashi', 's.takahashi@example.com', '$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq', true, false); /* password: "password" */

INSERT INTO m_group VALUES (1, 'Group A');
INSERT INTO m_group VALUES (2, 'Group B');
INSERT INTO m_group VALUES (3, 'Group C');

INSERT INTO m_authority VALUES (1, 'ROLE_ADMIN');
INSERT INTO m_authority VALUES (2, 'ROLE_ACTUATOR');

INSERT INTO r_user_group VALUES (1, 1);
INSERT INTO r_user_group VALUES (2, 1);
INSERT INTO r_user_group VALUES (1, 2);

INSERT INTO r_user_authority VALUES (1, 1);
INSERT INTO r_user_authority VALUES (1, 2);

INSERT INTO r_group_authority VALUES (1, 1);

COMMIT;
