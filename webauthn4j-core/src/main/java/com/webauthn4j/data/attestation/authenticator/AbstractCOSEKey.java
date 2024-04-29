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

package com.webauthn4j.data.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.util.ArrayUtil;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public abstract class AbstractCOSEKey implements COSEKey {

    @JsonProperty("2")
    private final byte[] keyId;

    @JsonProperty("3")
    private final COSEAlgorithmIdentifier algorithm;

    @JsonProperty("4")
    private final List<COSEKeyOperation> keyOps;

    @JsonProperty("5")
    private final byte[] baseIV;

    @SuppressWarnings("SameParameterValue")
    @JsonCreator
    AbstractCOSEKey(
            @Nullable @JsonProperty("2") byte[] keyId,
            @Nullable @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @Nullable @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @Nullable @JsonProperty("5") byte[] baseIV
    ) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.keyOps = keyOps;
        this.baseIV = baseIV;
    }

    @JsonProperty("1")
    public abstract @Nullable COSEKeyType getKeyType();

    public @Nullable byte[] getKeyId() {
        return ArrayUtil.clone(keyId);
    }

    public @Nullable COSEAlgorithmIdentifier getAlgorithm() {
        return algorithm;
    }

    public @Nullable List<COSEKeyOperation> getKeyOps() {
        return keyOps;
    }

    public @Nullable byte[] getBaseIV() {
        return ArrayUtil.clone(baseIV);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractCOSEKey that = (AbstractCOSEKey) o;
        return Arrays.equals(keyId, that.keyId) &&
                Objects.equals(algorithm, that.algorithm) &&
                Objects.equals(keyOps, that.keyOps) &&
                Arrays.equals(baseIV, that.baseIV);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(algorithm, keyOps);
        result = 31 * result + Arrays.hashCode(keyId);
        result = 31 * result + Arrays.hashCode(baseIV);
        return result;
    }
}
