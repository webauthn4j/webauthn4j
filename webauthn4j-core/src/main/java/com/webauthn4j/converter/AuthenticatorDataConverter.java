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

package com.webauthn4j.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.converter.jackson.ObjectMapperUtil;
import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;
import com.webauthn4j.util.UnsignedNumberUtil;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.Map;

public class AuthenticatorDataConverter {

    private ObjectMapper cborMapper;

    public byte[] convert(AuthenticatorData source) {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] rpIdHash = source.getRpIdHash();
            byteArrayOutputStream.write(rpIdHash);
            byteArrayOutputStream.write(new byte[]{source.getFlags()});
            byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(source.getSignCount()));
            if (source.getAttestedCredentialData() != null) {
                byteArrayOutputStream.write(convert(source.getAttestedCredentialData()));
            }
            byteArrayOutputStream.write(convert(source.getExtensions()));
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private byte[] convert(AttestedCredentialData attestationData) throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(attestationData.getAaGuid());
        byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(attestationData.getCredentialId().length));
        byteArrayOutputStream.write(attestationData.getCredentialId());
        byteArrayOutputStream.write(convert(attestationData.getCredentialPublicKey()));
        return byteArrayOutputStream.toByteArray();
    }

    public AuthenticatorData convert(byte[] value) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(value);

        byte[] rpIdHash = new byte[32];
        byteBuffer.get(rpIdHash, 0, 32);
        byte flags = byteBuffer.get();
        long counter = UnsignedNumberUtil.getUnsignedInt(byteBuffer);

        AttestedCredentialData attestationData;
        Map<String, AuthenticatorExtensionOutput> extensions;
        if (AuthenticatorData.checkFlagAT(flags)) {
            attestationData = convertToAttestedCredentialData(byteBuffer);
        } else {
            attestationData = null;
        }
        if (AuthenticatorData.checkFlagED(flags)) {
            extensions = convertToExtensions(byteBuffer);
        } else {
            extensions = Collections.emptyMap();
        }

        return new AuthenticatorData(rpIdHash, flags, counter, attestationData, extensions);
    }

    private AttestedCredentialData convertToAttestedCredentialData(ByteBuffer byteBuffer) {
        byte[] aaGuid = new byte[16];
        byteBuffer.get(aaGuid, 0, 16);
        int length = UnsignedNumberUtil.getUnsignedShort(byteBuffer);
        byte[] credentialId = new byte[length];
        byteBuffer.get(credentialId, 0, length);
        byte[] remaining = new byte[byteBuffer.remaining()];
        byteBuffer.get(remaining);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(remaining);
        CredentialPublicKey credentialPublicKey = convertToCredentialPublicKey(byteArrayInputStream);
        AttestedCredentialData attestationData = new AttestedCredentialData(aaGuid, credentialId, credentialPublicKey);
        int extensionsBufferLength = byteArrayInputStream.available();
        byteBuffer.position(byteBuffer.position() - extensionsBufferLength);
        return attestationData;
    }

    private CredentialPublicKey convertToCredentialPublicKey(InputStream inputStream) {
        try {
            return getCborMapper().readValue(inputStream, CredentialPublicKey.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    Map<String, AuthenticatorExtensionOutput> convertToExtensions(ByteBuffer byteBuffer) {
        if (byteBuffer.remaining() == 0) {
            return Collections.emptyMap();
        }
        byte[] remaining = new byte[byteBuffer.remaining()];
        byteBuffer.get(remaining);
        try {
            return getCborMapper().readValue(remaining, new TypeReference<Map<String, AuthenticatorExtensionOutput>>() {
            });
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    byte[] convert(Map<String, AuthenticatorExtensionOutput> extensions) {
        try {
            if (extensions == null || extensions.isEmpty()) {
                return new byte[0];
            } else {
                return getCborMapper().writeValueAsBytes(extensions);
            }
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    byte[] convert(CredentialPublicKey credentialPublicKey) throws JsonProcessingException {
        return getCborMapper().writeValueAsBytes(credentialPublicKey);
    }

    private ObjectMapper getCborMapper() {
        if (cborMapper == null) {
            cborMapper = ObjectMapperUtil.createCBORMapper();
        }
        return cborMapper;
    }


}
