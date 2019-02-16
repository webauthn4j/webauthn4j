/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.metadata.data.toc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

/**
 * Created by ynojima on 2017/09/08.
 */
public enum AuthenticatorStatus {
    FIDO_CERTIFIED("FIDO_CERTIFIED"),
    NOT_FIDO_CERTIFIED("NOT_FIDO_CERTIFIED"),
    USER_VERIFICATION_BYPASS("USER_VERIFICATION_BYPASS"),
    ATTESTATION_KEY_COMPROMISE("ATTESTATION_KEY_COMPROMISE"),
    USER_KEY_REMOTE_COMPROMISE("USER_KEY_REMOTE_COMPROMISE"),
    USER_KEY_PHYSICAL_COMPROMISE("USER_KEY_PHYSICAL_COMPROMISE"),
    UPDATE_AVAILABLE("UPDATE_AVAILABLE"),
    REVOKED("REVOKED"),
    SELF_ASSERTION_SUBMITTED("SELF_ASSERTION_SUBMITTED"),
    FIDO_CERTIFIED_L1("FIDO_CERTIFIED_L1"),
    FIDO_CERTIFIED_L1_PLUS("FIDO_CERTIFIED_L1plus"),
    FIDO_CERTIFIED_L2("FIDO_CERTIFIED_L2"),
    FIDO_CERTIFIED_L2_PLUS("FIDO_CERTIFIED_L2plus"),
    FIDO_CERTIFIED_L3("FIDO_CERTIFIED_L3"),
    FIDO_CERTIFIED_L3_PLUS("FIDO_CERTIFIED_L3plus");

    private final String value;

    AuthenticatorStatus(String value) {
        this.value = value;
    }

    @JsonCreator
    public static AuthenticatorStatus create(String value) throws InvalidFormatException {
        switch (value) {
            case "NOT_FIDO_CERTIFIED":
                return NOT_FIDO_CERTIFIED;
            case "FIDO_CERTIFIED":
                return FIDO_CERTIFIED;
            case "USER_VERIFICATION_BYPASS":
                return USER_VERIFICATION_BYPASS;
            case "ATTESTATION_KEY_COMPROMISE":
                return ATTESTATION_KEY_COMPROMISE;
            case "USER_KEY_REMOTE_COMPROMISE":
                return USER_KEY_REMOTE_COMPROMISE;
            case "USER_KEY_PHYSICAL_COMPROMISE":
                return USER_KEY_PHYSICAL_COMPROMISE;
            case "UPDATE_AVAILABLE":
                return UPDATE_AVAILABLE;
            case "REVOKED":
                return REVOKED;
            case "SELF_ASSERTION_SUBMITTED":
                return SELF_ASSERTION_SUBMITTED;
            case "FIDO_CERTIFIED_L1":
                return FIDO_CERTIFIED_L1;
            case "FIDO_CERTIFIED_L1plus":
                return FIDO_CERTIFIED_L1_PLUS;
            case "FIDO_CERTIFIED_L2":
                return FIDO_CERTIFIED_L2;
            case "FIDO_CERTIFIED_L2plus":
                return FIDO_CERTIFIED_L2_PLUS;
            case "FIDO_CERTIFIED_L3":
                return FIDO_CERTIFIED_L3;
            case "FIDO_CERTIFIED_L3plus":
                return FIDO_CERTIFIED_L3_PLUS;
            default:
                throw new InvalidFormatException(null, "value is out of range", value, AuthenticatorStatus.class);
        }
    }

    @JsonValue
    public String getValue() {
        return value;
    }


}
