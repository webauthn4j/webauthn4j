/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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
import org.jetbrains.annotations.NotNull;

/**
 * This enumeration describes the status of an authenticator webauthn as identified by its AAID and potentially some additional information (such as a specific attestation key).
 */
public enum AuthenticatorStatus {
    /**
     * This authenticator has passed FIDO functional certification.
     * This certification scheme is phased out and will be replaced by FIDO_CERTIFIED_L1.
     */
    FIDO_CERTIFIED("FIDO_CERTIFIED"),
    /**
     * This authenticator is not FIDO certified.
     */
    NOT_FIDO_CERTIFIED("NOT_FIDO_CERTIFIED"),
    /**
     * Indicates that malware is able to bypass the user verification.
     * This means that the authenticator could be used without the user’s consent and potentially even without the user’s knowledge.
     */
    USER_VERIFICATION_BYPASS("USER_VERIFICATION_BYPASS"),
    /**
     * Indicates that an attestation key for this authenticator is known to be compromised.
     * The relying party SHOULD check the certificate field and use it to identify the compromised authenticator batch.
     * If the certificate field is not set, the relying party should reject all new registrations of the compromised authenticator.
     * The Authenticator manufacturer should set the date to the date when compromise has occurred.
     */
    ATTESTATION_KEY_COMPROMISE("ATTESTATION_KEY_COMPROMISE"),
    /**
     * This authenticator has identified weaknesses that allow registered keys to be compromised and should not be trusted.
     * This would include both, e.g. weak entropy that causes predictable keys to be generated or side channels that allow keys or signatures to be forged, guessed or extracted.
     */
    USER_KEY_REMOTE_COMPROMISE("USER_KEY_REMOTE_COMPROMISE"),
    /**
     * This authenticator has known weaknesses in its key protection mechanism(s) that allow user keys to be extracted by an adversary in physical possession of the device.
     */
    USER_KEY_PHYSICAL_COMPROMISE("USER_KEY_PHYSICAL_COMPROMISE"),
    /**
     * A software or firmware update is available for the device.
     * The Authenticator manufacturer should set the url to the URL where users can obtain an update and the date the update was published.
     * When this status code is used, then the field authenticatorVersion in the authenticator Metadata Statement [FIDOMetadataStatement] MUST be updated,
     * if the update fixes severe security issues, e.g. the ones reported by preceding StatusReport entries with status code
     * USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE, USER_KEY_PHYSICAL_COMPROMISE, REVOKED.
     * The Relying party MUST reject the Metadata Statement if the authenticatorVersion has not increased
     */
    UPDATE_AVAILABLE("UPDATE_AVAILABLE"),
    /**
     * The FIDO Alliance has determined that this authenticator should not be trusted for any reason.
     * For example if it is known to be a fraudulent product or contain a deliberate backdoor.
     * Relying parties SHOULD reject any future registration of this authenticator model.
     */
    REVOKED("REVOKED"),
    /**
     * The authenticator vendor has completed and submitted the self-certification checklist to the FIDO Alliance.
     * If this completed checklist is publicly available, the URL will be specified in url.
     */
    SELF_ASSERTION_SUBMITTED("SELF_ASSERTION_SUBMITTED"),
    /**
     * The authenticator has passed FIDO Authenticator certification at level 1.
     * This level is the more strict successor of FIDO_CERTIFIED.
     */
    FIDO_CERTIFIED_L1("FIDO_CERTIFIED_L1"),
    /**
     * The authenticator has passed FIDO Authenticator certification at level 1+. This level is the more than level 1.
     */
    FIDO_CERTIFIED_L1_PLUS("FIDO_CERTIFIED_L1plus"),
    /**
     * The authenticator has passed FIDO Authenticator certification at level 2. This level is more strict than level 1+.
     */
    FIDO_CERTIFIED_L2("FIDO_CERTIFIED_L2"),
    /**
     * The authenticator has passed FIDO Authenticator certification at level 2+. This level is more strict than level 2.
     */
    FIDO_CERTIFIED_L2_PLUS("FIDO_CERTIFIED_L2plus"),
    /**
     * The authenticator has passed FIDO Authenticator certification at level 3. This level is more strict than level 2+.
     */
    FIDO_CERTIFIED_L3("FIDO_CERTIFIED_L3"),
    /**
     * The authenticator has passed FIDO Authenticator certification at level 3+. This level is more strict than level 3.
     */
    FIDO_CERTIFIED_L3_PLUS("FIDO_CERTIFIED_L3plus");

    @NotNull
    private final String value;

    AuthenticatorStatus(@NotNull String value) {
        this.value = value;
    }

    @NotNull
    public static AuthenticatorStatus create(@NotNull String value) {
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
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @NotNull
    @JsonCreator
    private static AuthenticatorStatus deserialize(@NotNull String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, AuthenticatorStatus.class);
        }
    }

    @JsonValue
    public String getValue() {
        return value;
    }


}
