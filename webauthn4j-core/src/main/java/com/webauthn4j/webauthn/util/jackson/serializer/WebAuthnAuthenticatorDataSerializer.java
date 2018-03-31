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

package com.webauthn4j.webauthn.util.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.webauthn.attestation.authenticator.AbstractCredentialPublicKey;
import com.webauthn4j.webauthn.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.webauthn.attestation.authenticator.WebAuthnAttestedCredentialData;
import com.webauthn4j.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import com.webauthn4j.webauthn.attestation.authenticator.extension.Extension;
import com.webauthn4j.webauthn.util.UnsignedNumberUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Jackson Serializer for WebAuthnAuthenticatorData
 */
public class WebAuthnAuthenticatorDataSerializer extends StdSerializer<WebAuthnAuthenticatorData> {

    private ObjectMapper objectMapper = new ObjectMapper(new CBORFactory());

    public WebAuthnAuthenticatorDataSerializer() {
        super(WebAuthnAuthenticatorData.class);
    }

    @Override
    public void serialize(WebAuthnAuthenticatorData value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeBinary(serialize(value));
    }

    byte[] serialize(WebAuthnAuthenticatorData value) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(value.getRpIdHash());
        byteArrayOutputStream.write(new byte[]{value.getFlags()});
        byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(value.getCounter()));
        if (value.getAttestationData() != null) {
            byteArrayOutputStream.write(serializeAttestationData(value.getAttestationData()));
        }
        byteArrayOutputStream.write(serializeExtensions(value.getExtensions()));
        return byteArrayOutputStream.toByteArray();
    }

    private byte[] serializeAttestationData(WebAuthnAttestedCredentialData attestationData) throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(attestationData.getAaGuid());
        byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(attestationData.getCredentialId().length));
        byteArrayOutputStream.write(attestationData.getCredentialId());
        byteArrayOutputStream.write(serializeCredentialPublicKey(attestationData.getCredentialPublicKey()));
        return byteArrayOutputStream.toByteArray();
    }

    private byte[] serializeExtensions(List<Extension> extensions) {
        return new byte[0]; //TODO: to be implemented
    }

    private byte[] serializeCredentialPublicKey(CredentialPublicKey credentialPublicKey) throws JsonProcessingException {
        return objectMapper.writeValueAsBytes(credentialPublicKey);
    }

}
