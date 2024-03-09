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

package com.webauthn4j.data.attestation.statement;

import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.nio.ByteBuffer;
import java.util.Objects;

public class TPMAObject {

    public static final int FIXED_TPM_BIT = 0b00000000000000000000000000000010;
    public static final int ST_CLEAR_BIT = 0b00000000000000000000000000000100;
    public static final int FIXED_PARENT_BIT = 0b00000000000000000000000000010000;
    public static final int SENSITIVE_DATA_ORIGIN_BIT = 0b00000000000000000000000000100000;
    public static final int USER_WITH_AUTH_BIT = 0b00000000000000000000000001000000;
    public static final int ADMIN_WITH_POLICY_BIT = 0b00000000000000000000000010000000;
    public static final int NO_DA_BIT = 0b00000000000000000000010000000000;
    public static final int ENCRYPTED_DUPLICATION_BIT = 0b00000000000000000000100000000000;
    public static final int RESTRICTED_BIT = 0b00000000000000010000000000000000;
    public static final int DECRYPT_BIT = 0b00000000000000100000000000000000;
    public static final int SIGN_ENCRYPT_BIT = 0b00000000000001000000000000000000;

    private final int value;

    public TPMAObject(int value) {
        this.value = value;
    }

    public boolean isFixedTPM() {
        return (value & FIXED_TPM_BIT) != 0;
    }

    public boolean isStClear() {
        return (value & ST_CLEAR_BIT) != 0;
    }


    public boolean isFixedParent() {
        return (value & FIXED_PARENT_BIT) != 0;
    }

    public boolean isSensitiveDataOrigin() {
        return (value & SENSITIVE_DATA_ORIGIN_BIT) != 0;
    }

    public boolean isUserWithAuth() {
        return (value & USER_WITH_AUTH_BIT) != 0;
    }

    public boolean isAdminWithPolicy() {
        return (value & ADMIN_WITH_POLICY_BIT) != 0;
    }

    public boolean isNoDA() {
        return (value & NO_DA_BIT) != 0;
    }

    public boolean isEncryptedDuplication() {
        return (value & ENCRYPTED_DUPLICATION_BIT) != 0;
    }

    public boolean isRestricted() {
        return (value & RESTRICTED_BIT) != 0;
    }

    public boolean isDecrypt() {
        return (value & DECRYPT_BIT) != 0;
    }

    public boolean isSignEncrypt() {
        return (value & SIGN_ENCRYPT_BIT) != 0;
    }

    public @NonNull byte[] getBytes() {
        return ByteBuffer.allocate(4).putInt(value).array();
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TPMAObject that = (TPMAObject) o;
        return value == that.value;
    }

    @Override
    public int hashCode() {

        return Objects.hash(value);
    }
}
