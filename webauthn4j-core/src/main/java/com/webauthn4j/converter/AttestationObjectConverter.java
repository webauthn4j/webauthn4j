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

import com.fasterxml.jackson.databind.JsonNode;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.JacksonUtil;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Converter for {@link AttestationObject}
 */
public class AttestationObjectConverter {

    private static final String SOURCE_NULL_CHECK_MESSAGE = "source must not be null";

    // ~ Instance fields
    // ================================================================================================
    private final CborConverter cborConverter;

    // ~ Constructors
    // ================================================================================================

    public AttestationObjectConverter(@NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.cborConverter = objectConverter.getCborConverter();
    }

    // ~ Methods
    // ================================================================================================

    /**
     * Converts from a base64url {@link String} to {@link AttestationObject}.
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    public @Nullable AttestationObject convert(@NotNull String source) {
        try {
            AssertUtil.notNull(source, SOURCE_NULL_CHECK_MESSAGE);
            byte[] value = Base64UrlUtil.decode(source);
            return convert(value);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts from a byte array to {@link AttestationObject}.
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    public @Nullable AttestationObject convert(@NotNull byte[] source) {
        try {
            AssertUtil.notNull(source, SOURCE_NULL_CHECK_MESSAGE);
            return cborConverter.readValue(source, AttestationObject.class);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts from a {@link AttestationObject} to byte[].
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public @NotNull byte[] convertToBytes(@NotNull AttestationObject source) {
        try {
            AssertUtil.notNull(source, SOURCE_NULL_CHECK_MESSAGE);
            return cborConverter.writeValueAsBytes(source);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts from a {@link AttestationObject} to {@link String}.
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public @NotNull String convertToBase64urlString(@NotNull AttestationObject source) {
        try {
            byte[] bytes = convertToBytes(source);
            return Base64UrlUtil.encodeToString(bytes);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Extract authenticatorData byte array from a attestationObject byte array.
     *
     * @param attestationObject the attestationObject byte array
     * @return the extracted authenticatorData byte array
     */
    public @Nullable byte[] extractAuthenticatorData(@NotNull byte[] attestationObject) {
        AssertUtil.notNull(attestationObject, "attestationObject must not be null");
        JsonNode authData = cborConverter.readTree(attestationObject).get("authData");
        return JacksonUtil.binaryValue(authData);
    }

    /**
     * Extract attestation statement byte array from a attestationObject byte array.
     *
     * @param attestationObject the attestationObject byte array
     * @return the extracted attestation statement byte array
     */
    public @Nullable byte[] extractAttestationStatement(@NotNull byte[] attestationObject) {
        AssertUtil.notNull(attestationObject, "attestationObject must not be null");
        JsonNode attStmt = cborConverter.readTree(attestationObject).get("attStmt");
        return cborConverter.writeValueAsBytes(attStmt);
    }


}
