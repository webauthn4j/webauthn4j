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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.WebAuthnAuthenticatorModule;
import com.webauthn4j.converter.jackson.deserializer.AuthenticationExtensionsAuthenticatorOutputsEnvelope;
import com.webauthn4j.converter.jackson.deserializer.CredentialPublicKeyEnvelope;
import com.webauthn4j.converter.util.AbstractCborConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.util.UnsignedNumberUtil;

import java.io.*;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Converter for {@link AuthenticatorData}
 */
public class AuthenticatorDataConverter extends AbstractCborConverter {
    public static final AuthenticatorDataConverter INSTANCE = new AuthenticatorDataConverter();

    //~ Constructors
    // ================================================================================================

    public AuthenticatorDataConverter() {
        this(new ObjectMapper(new CBORFactory()));
    }

    public AuthenticatorDataConverter(ObjectMapper mapper) {
        super(mapper, new WebAuthnAuthenticatorModule());

    }

    //~ Methods
    // ================================================================================================

    /**
     * Converts from a {@link AuthenticatorData} to byte[].
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
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

    /**
     * Converts from a byte array to {@link AuthenticatorData}.
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    public <T extends ExtensionAuthenticatorOutput> AuthenticatorData<T> convert(byte[] source) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(source);

            byte[] rpIdHash = new byte[32];
            byteBuffer.get(rpIdHash, 0, 32);
            byte flags = byteBuffer.get();
            long counter = UnsignedNumberUtil.getUnsignedInt(byteBuffer);

            AttestedCredentialData attestationData;
            AuthenticationExtensionsAuthenticatorOutputs<T> extensions;
            if (AuthenticatorData.checkFlagAT(flags)) {
                attestationData = convertToAttestedCredentialData(byteBuffer);
            } else {
                attestationData = null;
            }
            if (AuthenticatorData.checkFlagED(flags)) {
                extensions = convertToExtensions(byteBuffer);
            } else {
                extensions = new AuthenticationExtensionsAuthenticatorOutputs<>();
            }
            if (byteBuffer.hasRemaining()) {
                throw new DataConversionException("provided data does not have proper byte layout");
            }

            return new AuthenticatorData<>(rpIdHash, flags, counter, attestationData, extensions);

        } catch (BufferUnderflowException e) {
            throw new DataConversionException("provided data does not have proper byte layout", e);
        }
    }

    private byte[] convert(AttestedCredentialData attestationData) throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(attestationData.getAaguid().getBytes());
        byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(attestationData.getCredentialId().length));
        byteArrayOutputStream.write(attestationData.getCredentialId());
        byteArrayOutputStream.write(convert(attestationData.getCredentialPublicKey()));
        return byteArrayOutputStream.toByteArray();
    }

    private AttestedCredentialData convertToAttestedCredentialData(ByteBuffer byteBuffer) {
        byte[] aaguidBytes = new byte[16];
        byteBuffer.get(aaguidBytes, 0, 16);
        AAGUID aaguid = new AAGUID(aaguidBytes);
        int length = UnsignedNumberUtil.getUnsignedShort(byteBuffer);
        byte[] credentialId = new byte[length];
        byteBuffer.get(credentialId, 0, length);
        byte[] remaining = new byte[byteBuffer.remaining()];
        byteBuffer.get(remaining);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(remaining);
        CredentialPublicKeyEnvelope credentialPublicKeyEnvelope = convertToCredentialPublicKey(byteArrayInputStream);
        CredentialPublicKey credentialPublicKey = credentialPublicKeyEnvelope.getCredentialPublicKey();
        AttestedCredentialData attestedCredentialData = new AttestedCredentialData(aaguid, credentialId, credentialPublicKey);
        int extensionsBufferLength = remaining.length - credentialPublicKeyEnvelope.getLength();
        byteBuffer.position(byteBuffer.position() - extensionsBufferLength);
        return attestedCredentialData;
    }

    private CredentialPublicKeyEnvelope convertToCredentialPublicKey(InputStream inputStream) {
        return this.readValue(inputStream, CredentialPublicKeyEnvelope.class);
    }

    private <T extends ExtensionAuthenticatorOutput> AuthenticationExtensionsAuthenticatorOutputs<T> convertToExtensions(ByteBuffer byteBuffer) {
        if (byteBuffer.remaining() == 0) {
            return new AuthenticationExtensionsAuthenticatorOutputs<>();
        }
        byte[] remaining = new byte[byteBuffer.remaining()];
        byteBuffer.get(remaining);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(remaining);
        AuthenticationExtensionsAuthenticatorOutputsEnvelope<T> envelope =
                this.readValue(byteArrayInputStream, AuthenticationExtensionsAuthenticatorOutputsEnvelope.class);
        int leftoverLength = remaining.length - envelope.getLength();
        byteBuffer.position(byteBuffer.position() - leftoverLength);
        return envelope.getAuthenticationExtensionsAuthenticatorOutputs();
    }

    byte[] convert(AuthenticationExtensionsAuthenticatorOutputs extensions) {
        if (extensions == null || extensions.isEmpty()) {
            return new byte[0];
        } else {
            return this.writeValueAsBytes(extensions);
        }
    }

    byte[] convert(CredentialPublicKey credentialPublicKey) {
        return this.writeValueAsBytes(credentialPublicKey);
    }
}
