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

package com.webauthn4j.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.COSEKeyOperation;
import com.webauthn4j.attestation.statement.COSEKeyType;

import java.io.Serializable;
import java.security.PublicKey;

@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.PROPERTY,
        property = "1")
@JsonSubTypes({
        @JsonSubTypes.Type(value = ECCredentialPublicKey.class, name = "1"),
        @JsonSubTypes.Type(value = ECCredentialPublicKey.class, name = "2"),
        @JsonSubTypes.Type(value = RSACredentialPublicKey.class, name = "3")
})
public interface CredentialPublicKey extends Serializable {

    boolean verifySignature(byte[] signature, byte[] data);

    @JsonIgnore
    PublicKey getPublicKey();

    COSEKeyType getKeyType();

    byte[] getKeyId();

    COSEAlgorithmIdentifier getAlgorithm();

    COSEKeyOperation[] getKeyOpts();

    byte[] getBaseIV();

    @JsonIgnore
    byte[] getBytes();

    void validate();
}
