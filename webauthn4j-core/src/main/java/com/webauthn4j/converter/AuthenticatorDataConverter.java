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

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.response.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.response.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.response.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.util.UnsignedNumberUtil;

import java.io.*;
import java.nio.ByteBuffer;

/**
 * Converter for {@link AuthenticatorData}
 */
public class AuthenticatorDataConverter {

    //~ Instance fields
    // ================================================================================================
    private CborConverter cborConverter;

    //~ Constructors
    // ================================================================================================

    public AuthenticatorDataConverter(Registry registry){
        cborConverter = new CborConverter(registry.getCborMapper());
    }


    //~ Methods
    // ================================================================================================

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
        byteArrayOutputStream.write(attestationData.getAaguid());
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
        AuthenticationExtensionsAuthenticatorOutputs extensions;
        if (AuthenticatorData.checkFlagAT(flags)) {
            attestationData = convertToAttestedCredentialData(byteBuffer);
        } else {
            attestationData = null;
        }
        if (AuthenticatorData.checkFlagED(flags)) {
            extensions = convertToExtensions(byteBuffer);
        } else {
            extensions = new AuthenticationExtensionsAuthenticatorOutputs();
        }
        if(byteBuffer.hasRemaining()){
            throw new DataConversionException("authenticatorData has surplus data");
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
        return cborConverter.readValue(inputStream, CredentialPublicKey.class);
    }

    AuthenticationExtensionsAuthenticatorOutputs convertToExtensions(ByteBuffer byteBuffer) {
        if (byteBuffer.remaining() == 0) {
            return new AuthenticationExtensionsAuthenticatorOutputs();
        }
        byte[] remaining = new byte[byteBuffer.remaining()];
        byteBuffer.get(remaining);
        return cborConverter.readValue(remaining, new TypeReference<AuthenticationExtensionsAuthenticatorOutputs>(){});
    }

    byte[] convert(AuthenticationExtensionsAuthenticatorOutputs extensions) {
        if (extensions == null || extensions.isEmpty()) {
            return new byte[0];
        } else {
            return cborConverter.writeValueAsBytes(extensions);
        }
    }

    byte[] convert(CredentialPublicKey credentialPublicKey) {
        return cborConverter.writeValueAsBytes(credentialPublicKey);
    }

}
