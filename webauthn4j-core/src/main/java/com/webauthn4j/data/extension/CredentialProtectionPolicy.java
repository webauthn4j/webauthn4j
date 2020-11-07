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

package com.webauthn4j.data.extension;

import org.checkerframework.checker.nullness.qual.NonNull;

public enum CredentialProtectionPolicy {

    USER_VERIFICATION_OPTIONAL("userVerificationOptional", (byte) 0x01),
    USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST("userVerificationOptionalWithCredentialIDList", (byte) 0x02),
    USER_VERIFICATION_REQUIRED("userVerificationRequired", (byte) 0x03);

    final String string;
    final byte value;

    CredentialProtectionPolicy(@NonNull String string, @NonNull byte value) {
        this.string = string;
        this.value = value;
    }

    public static CredentialProtectionPolicy create(@NonNull String string) {
        switch (string) {
            case "userVerificationOptional":
                return USER_VERIFICATION_OPTIONAL;
            case "userVerificationOptionalWithCredentialIDList":
                return USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST;
            case "userVerificationRequired":
                return USER_VERIFICATION_REQUIRED;
            default:
                throw new IllegalArgumentException("string '" + string + "' is out of range");
        }
    }

    public static CredentialProtectionPolicy create(byte value) {
        switch (value) {
            case 0x01:
                return USER_VERIFICATION_OPTIONAL;
            case 0x02:
                return USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST;
            case 0x03:
                return USER_VERIFICATION_REQUIRED;
            default:
                throw new IllegalArgumentException("value" + value + "' is out of range");
        }
    }

    @Override
    public String toString() {
        return string;
    }

    public byte toByte() {
        return value;
    }

}
