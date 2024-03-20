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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        property = "1")
@JsonSubTypes({
        @JsonSubTypes.Type(value = EdDSACOSEKey.class, name = "1"),
        @JsonSubTypes.Type(value = EC2COSEKey.class, name = "2"),
        @JsonSubTypes.Type(value = RSACOSEKey.class, name = "3")
})
public interface COSEKey {

    boolean hasPublicKey();

    boolean hasPrivateKey();

    @JsonIgnore
    @Nullable PublicKey getPublicKey();

    @JsonIgnore
    @Nullable PrivateKey getPrivateKey();

    @Nullable COSEKeyType getKeyType();

    @Nullable byte[] getKeyId();

    @Nullable COSEAlgorithmIdentifier getAlgorithm();

    @Nullable List<COSEKeyOperation> getKeyOps();

    @Nullable byte[] getBaseIV();

    void validate();
}
