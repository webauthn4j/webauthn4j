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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.data.UserVerificationMethod;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.AbstractList;
import java.util.Arrays;

public class UvmEntry extends AbstractList<Number> {

    private final Number[] array;

    @JsonCreator
    public UvmEntry(@NonNull Number[] value) {
        AssertUtil.notNull(value, "value must not be null");
        this.array = value.clone();
    }

    public UvmEntry(@NonNull UserVerificationMethod userVerificationMethod, @NonNull KeyProtectionType keyProtectionType, @NonNull MatcherProtectionType matcherProtectionType) {
        Number[] numbers = new Number[3];
        numbers[0] = userVerificationMethod.getValue();
        numbers[1] = keyProtectionType.getValue();
        numbers[2] = matcherProtectionType.getValue();
        this.array = numbers;
    }

    @JsonValue
    private @NonNull Number[] getValue() {
        return array;
    }

    @Override
    public @NonNull Number get(int index) {
        return array[index];
    }

    @Override
    public int size() {
        return array.length;
    }

    public @NonNull UserVerificationMethod getUserVerificationMethod() {
        if (array.length <= 0) {
            throw new IllegalStateException("UvmEntry doesn't have sufficient elements. UserVerificationMethod is not included.");
        }
        return UserVerificationMethod.create(array[0].intValue());
    }

    public @NonNull KeyProtectionType getKeyProtectionType() {
        if (array.length <= 1) {
            throw new IllegalStateException("UvmEntry doesn't have sufficient elements. KeyProtectionType is not included.");
        }
        return KeyProtectionType.create(array[1].intValue());
    }

    public @NonNull MatcherProtectionType getMatcherProtectionType() {
        if (array.length <= 2) {
            throw new IllegalStateException("UvmEntry doesn't have sufficient elements. MatcherProtectionType is not included.");
        }
        return MatcherProtectionType.create(array[2].intValue());
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UvmEntry uvmEntry = (UvmEntry) o;
        return Arrays.equals(array, uvmEntry.array);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(array);
    }

}
