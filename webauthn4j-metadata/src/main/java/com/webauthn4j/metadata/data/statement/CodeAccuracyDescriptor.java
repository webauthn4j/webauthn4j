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

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

/**
 * The CodeAccuracyDescriptor describes the relevant accuracy/complexity aspects of passcode user verification methods.
 */
public class CodeAccuracyDescriptor {

    @NonNull private final Integer base;
    @NonNull private final Integer minLength;
    @Nullable private final Integer maxRetries;
    @Nullable private final Integer blockSlowdown;

    @JsonCreator
    public CodeAccuracyDescriptor(
            @NonNull @JsonProperty("base") Integer base,
            @NonNull @JsonProperty("minLength") Integer minLength,
            @Nullable @JsonProperty("maxRetries") Integer maxRetries,
            @Nullable @JsonProperty("blockSlowdown") Integer blockSlowdown) {
        this.base = base;
        this.minLength = minLength;
        this.maxRetries = maxRetries;
        this.blockSlowdown = blockSlowdown;
    }

    @NonNull
    public Integer getBase() {
        return base;
    }

    @NonNull
    public Integer getMinLength() {
        return minLength;
    }

    @Nullable
    public Integer getMaxRetries() {
        return maxRetries;
    }

    @Nullable
    public Integer getBlockSlowdown() {
        return blockSlowdown;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CodeAccuracyDescriptor that = (CodeAccuracyDescriptor) o;
        return base.equals(that.base) && minLength.equals(that.minLength) && Objects.equals(maxRetries, that.maxRetries) && Objects.equals(blockSlowdown, that.blockSlowdown);
    }

    @Override
    public int hashCode() {
        return Objects.hash(base, minLength, maxRetries, blockSlowdown);
    }
}
