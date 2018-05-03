package net.sharplab.springframework.security.webauthn.sample.domain.constant;

/**
 * Message ID constants
 */
@SuppressWarnings("squid:S2068")
public class MessageCodes {

    public class Error {
        public class User {
            public static final String USER_NOT_FOUND = "e.user.user_not_found";
            public static final String EMAIL_ADDRESS_IS_ALREADY_USED = "e.user.email_address_is_already_used";
            public static final String BAD_CHALLENGE = "e.user.bad_challenge";

            private User() {
            }
        }

        public class Group {
            public static final String GROUP_NOT_FOUND = "e.group.group_not_found";

            private Group() {
            }
        }

        public class Authority {
            public static final String AUTHORITY_NOT_FOUND = "e.authority.authority_not_found";

            private Authority() {
            }
        }

        public static final String UNKNOWN = "e.unknown";

        private Error() {
        }
    }

    public class Success {
        public class User {
            public static final String USER_CREATED = "s.user.user_created";

            public static final String USER_UPDATED = "s.user.user_updated";

            public static final String USER_PASSWORD_UPDATED = "s.user.user_password_updated";

            public static final String USER_DELETED = "s.user.user_deleted";

            private User() {
            }
        }

        public class Profile {
            public static final String PROFILE_UPDATED = "s.profile.profile_updated";

            private Profile() {
            }
        }

        public class Group {
            public static final String GROUP_CREATED = "s.group.group_created";

            public static final String GROUP_UPDATED = "s.group.group_updated";

            public static final String GROUP_DELETED = "s.group.group_deleted";

            private Group() {
            }
        }

        public class Authority {
            public static final String AUTHORITY_CREATED = "s.authority.authority_created";

            public static final String AUTHORITY_UPDATED = "s.authority.authority_updated";

            public static final String AUTHORITY_DELETED = "s.authority.authority_deleted";

            private Authority() {
            }
        }
    }

    private MessageCodes() {
    }
}
