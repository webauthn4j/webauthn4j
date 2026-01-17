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

package com.webauthn4j.converter;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.deserializer.cbor.AuthenticationExtensionsAuthenticatorOutputsEnvelope;
import com.webauthn4j.converter.jackson.deserializer.cbor.COSEKeyEnvelope;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.UnsignedNumberUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.core.type.TypeReference;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.Buffer;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Converter for {@link AuthenticatorData}
 *
 * This class provides functionality to convert between AuthenticatorData objects and their binary representation
 * for WebAuthn processing.
 */
public class AuthenticatorDataConverter {

    private static final int RPID_HASH_LENGTH = 32;
    private static final int FLAGS_LENGTH = 1;
    private static final int COUNTER_LENGTH = 4;

    private static final int AAGUID_LENGTH = 16;
    private static final int L_LENGTH = 2;

    private static final int COUNTER_INDEX = RPID_HASH_LENGTH + FLAGS_LENGTH;
    private static final int ATTESTED_CREDENTIAL_DATA_INDEX = RPID_HASH_LENGTH + FLAGS_LENGTH + COUNTER_LENGTH;
    private static final int L_INDEX = ATTESTED_CREDENTIAL_DATA_INDEX + AAGUID_LENGTH;
    private static final int CREDENTIAL_ID_INDEX = L_INDEX + L_LENGTH;

    //~ Instance fields
    // ================================================================================================
    private final ObjectConverter objectConverter;
    private final AttestedCredentialDataConverter attestedCredentialDataConverter;

    //~ Constructors
    // ================================================================================================

    /**
     * Creates a new AuthenticatorDataConverter instance.
     *
     * @param objectConverter converter for data serialization
     * @throws IllegalArgumentException if objectConverter is null
     */
    public AuthenticatorDataConverter(@NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.objectConverter = objectConverter;
        this.attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);
    }

    //~ Methods
    // ================================================================================================

    /**
     * Converts from a {@link AuthenticatorData} to byte[].
     *
     * @param source the source object to convert
     * @param <T>    the type of extension authenticator output
     * @return the converted byte array
     * @throws DataConversionException if conversion fails
     * @throws UncheckedIOException if an I/O error occurs
     */
    public <T extends ExtensionAuthenticatorOutput> @NotNull byte[] convert(@NotNull AuthenticatorData<T> source) {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] rpIdHash = source.getRpIdHash();
            byteArrayOutputStream.write(rpIdHash);
            byteArrayOutputStream.write(new byte[]{source.getFlags()});
            byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(source.getSignCount()));
            if (source.getAttestedCredentialData() != null) {
                byteArrayOutputStream.write(attestedCredentialDataConverter.convert(source.getAttestedCredentialData()));
            }
            byteArrayOutputStream.write(convert(source.getExtensions()));
            return byteArrayOutputStream.toByteArray();
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Converts from a byte array to {@link AuthenticatorData}.
     *
     * @param <T>    the type of extension authenticator output
     * @param source the source byte array to convert
     * @return the converted object
     * @throws DataConversionException if conversion fails
     */
    public <T extends ExtensionAuthenticatorOutput> @NotNull AuthenticatorData<T> convert(@NotNull byte[] source) {
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(source);

            byte[] rpIdHash = new byte[RPID_HASH_LENGTH];
            byteBuffer.get(rpIdHash, 0, RPID_HASH_LENGTH);
            byte flags = byteBuffer.get();
            long counter = UnsignedNumberUtil.getUnsignedInt(byteBuffer);

            AttestedCredentialData attestedCredentialData;
            AuthenticationExtensionsAuthenticatorOutputs<T> extensions;
            if (AuthenticatorData.checkFlagAT(flags)) {
                if (byteBuffer.hasRemaining()) {
                    attestedCredentialData = attestedCredentialDataConverter.convert(byteBuffer);
                }
                else {
                    attestedCredentialData = null; // Apple App Attest API assertion has AT flag even though they don't have attestedCredentialData.
                }
            }
            else {
                attestedCredentialData = null;
            }
            if (AuthenticatorData.checkFlagED(flags)) {
                extensions = convertToExtensions(byteBuffer);
            }
            else {
                extensions = new AuthenticationExtensionsAuthenticatorOutputs<>();
            }
            if (byteBuffer.hasRemaining()) {
                throw new DataConversionException("provided data does not have proper byte layout");
            }

            return new AuthenticatorData<>(rpIdHash, flags, counter, attestedCredentialData, extensions);

        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        } catch (BufferUnderflowException e) {
            throw new DataConversionException("provided data does not have proper byte layout", e);
        }
    }

    /**
     * Extract attestedCredentialData byte array from an authenticatorData byte array.
     *
     * @param authenticatorData the authenticatorData byte array
     * @return the extracted attestedCredentialData byte array
     * @throws IllegalArgumentException if the input format is invalid
     */
    public @NotNull byte[] extractAttestedCredentialData(@NotNull byte[] authenticatorData) {
        byte[] lengthBytes = Arrays.copyOfRange(authenticatorData, L_INDEX, CREDENTIAL_ID_INDEX);
        int credentialIdLength = UnsignedNumberUtil.getUnsignedShort(lengthBytes);
        int credentialPublicKeyIndex = CREDENTIAL_ID_INDEX + credentialIdLength;

        byte[] attestedCredentialDataBytes = Arrays.copyOfRange(authenticatorData, credentialPublicKeyIndex, authenticatorData.length);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(attestedCredentialDataBytes);
        COSEKeyEnvelope coseKeyEnvelope = attestedCredentialDataConverter.convertToCredentialPublicKey(byteArrayInputStream);
        int credentialPublicKeyLength = coseKeyEnvelope.getLength();
        int attestedCredentialDataLength = AAGUID_LENGTH + L_LENGTH + credentialIdLength + credentialPublicKeyLength;
        return Arrays.copyOfRange(authenticatorData, ATTESTED_CREDENTIAL_DATA_INDEX, ATTESTED_CREDENTIAL_DATA_INDEX + attestedCredentialDataLength);
    }

    /**
     * Extract signCount from an authenticatorData byte array.
     *
     * @param authenticatorData the authenticatorData byte array
     * @return the extracted signCount
     */
    public long extractSignCount(@NotNull byte[] authenticatorData) {
        byte[] counterBytes = Arrays.copyOfRange(authenticatorData, COUNTER_INDEX, COUNTER_INDEX + COUNTER_LENGTH);
        return UnsignedNumberUtil.getUnsignedInt(counterBytes);
    }


    @NotNull <T extends ExtensionAuthenticatorOutput> byte[] convert(@Nullable AuthenticationExtensionsAuthenticatorOutputs<T> extensions) {
        if (extensions == null || extensions.getKeys().isEmpty()) {
            return new byte[0];
        }
        else {
            return objectConverter.getCborMapper().writeValueAsBytes(extensions);
        }
    }

    @SuppressWarnings("RedundantCast")
    <T extends ExtensionAuthenticatorOutput> @Nullable AuthenticationExtensionsAuthenticatorOutputs<T> convertToExtensions(@NotNull ByteBuffer byteBuffer) {
        // Since convertToExtensions is called when ED flag is set, return empty AuthenticationExtensionsAuthenticatorOutputs even when remaining is zero.
        if (byteBuffer.remaining() == 0) {
            return new AuthenticationExtensionsAuthenticatorOutputs<>();
        }
        byte[] remaining = new byte[byteBuffer.remaining()];
        byteBuffer.get(remaining);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(remaining);
        AuthenticationExtensionsAuthenticatorOutputsEnvelope<T> envelope =
                objectConverter.getCborMapper().readValue(byteArrayInputStream, new TypeReference<AuthenticationExtensionsAuthenticatorOutputsEnvelope<T>>() {
                });
        if (envelope == null) {
            return null;
        }
        int leftoverLength = remaining.length - envelope.getLength();
        //This cast is necessary to be complied with JDK 17 when targeting JDK 8
        ((Buffer)byteBuffer).position(((Buffer)byteBuffer).position() - leftoverLength);
        return envelope.getAuthenticationExtensionsAuthenticatorOutputs();
    }


}
