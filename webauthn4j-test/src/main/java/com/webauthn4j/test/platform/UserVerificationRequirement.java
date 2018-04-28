package com.webauthn4j.test.platform;

import com.webauthn4j.util.Experimental;

@Experimental
public enum  UserVerificationRequirement {
    REQUIRED,
    PREFERRED,
    DISCOURAGED
}
