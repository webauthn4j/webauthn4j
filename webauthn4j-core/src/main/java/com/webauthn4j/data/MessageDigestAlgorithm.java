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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.MessageDigestUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.security.MessageDigest;
import java.util.Objects;

public class MessageDigestAlgorithm {

    public static final MessageDigestAlgorithm SHA1 = new MessageDigestAlgorithm("SHA-1");
    public static final MessageDigestAlgorithm SHA256 = new MessageDigestAlgorithm("SHA-256");
    public static final MessageDigestAlgorithm SHA384 = new MessageDigestAlgorithm("SHA-384");
    public static final MessageDigestAlgorithm SHA512 = new MessageDigestAlgorithm("SHA-512");

    private final String jcaName;

    private MessageDigestAlgorithm(@NonNull String jcaName) {
        this.jcaName = jcaName;
    }

    public static @NonNull MessageDigestAlgorithm create(@NonNull String jcaName) {
        AssertUtil.notNull(jcaName, "jcaName must not be null");
        return new MessageDigestAlgorithm(jcaName);
    }

    @SuppressWarnings("unused")
    @JsonCreator
    private static @NonNull MessageDigestAlgorithm deserialize(String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, MessageDigestAlgorithm.class);
        }
    }

    @JsonValue
    public @NonNull String getJcaName() {
        return jcaName;
    }

    public @NonNull MessageDigest createMessageDigestObject() {
        return MessageDigestUtil.createMessageDigest(jcaName);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MessageDigestAlgorithm that = (MessageDigestAlgorithm) o;
        return Objects.equals(jcaName, that.jcaName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(jcaName);
    }

    @Override
    public String toString() {
        return jcaName;
    }
}
