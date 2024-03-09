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

import java.math.BigInteger;
import java.util.Objects;

/**
 * The PatternAccuracyDescriptor describes relevant accuracy/complexity aspects in the case that a pattern is used as the user verification method.
 */
public class PatternAccuracyDescriptor {

    @NonNull private final BigInteger minComplexity;
    @Nullable private final Integer maxRetries;
    @Nullable private final Integer blockSlowdown;

    @JsonCreator
    public PatternAccuracyDescriptor(
            @JsonProperty("minComplexity") @NonNull BigInteger minComplexity,
            @JsonProperty("maxRetries") @Nullable Integer maxRetries,
            @JsonProperty("blockSlowdown") @Nullable Integer blockSlowdown) {
        this.minComplexity = minComplexity;
        this.maxRetries = maxRetries;
        this.blockSlowdown = blockSlowdown;
    }

    @NonNull public BigInteger getMinComplexity() {
        return minComplexity;
    }

    @Nullable public Integer getMaxRetries() {
        return maxRetries;
    }

    @Nullable public Integer getBlockSlowdown() {
        return blockSlowdown;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PatternAccuracyDescriptor that = (PatternAccuracyDescriptor) o;
        return Objects.equals(minComplexity, that.minComplexity) &&
                Objects.equals(maxRetries, that.maxRetries) &&
                Objects.equals(blockSlowdown, that.blockSlowdown);
    }

    @Override
    public int hashCode() {

        return Objects.hash(minComplexity, maxRetries, blockSlowdown);
    }
}
