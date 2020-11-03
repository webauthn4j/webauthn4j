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

import com.webauthn4j.converter.jackson.JacksonUtil;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

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

    public AttestationObjectConverter(@NonNull ObjectConverter objectConverter) {
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
    public @NonNull AttestationObject convert(@NonNull String source) {
        AssertUtil.notNull(source, SOURCE_NULL_CHECK_MESSAGE);
        byte[] value = Base64UrlUtil.decode(source);
        return convert(value);
    }

    /**
     * Converts from a byte array to {@link AttestationObject}.
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    public @NonNull AttestationObject convert(@NonNull byte[] source) {
        AssertUtil.notNull(source, SOURCE_NULL_CHECK_MESSAGE);
        return cborConverter.readValue(source, AttestationObject.class);
    }

    /**
     * Converts from a {@link AttestationObject} to byte[].
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public @NonNull byte[] convertToBytes(@NonNull AttestationObject source) {
        AssertUtil.notNull(source, SOURCE_NULL_CHECK_MESSAGE);
        return cborConverter.writeValueAsBytes(source);
    }

    /**
     * Converts from a {@link AttestationObject} to {@link String}.
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public @NonNull String convertToBase64urlString(@NonNull AttestationObject source) {
        byte[] bytes = convertToBytes(source);
        return Base64UrlUtil.encodeToString(bytes);
    }

    /**
     * Extract authenticatorData byte array from a attestationObject byte array.
     *
     * @param attestationObject the attestationObject byte array
     * @return the extracted authenticatorData byte array
     */
    public @NonNull byte[] extractAuthenticatorData(@NonNull byte[] attestationObject) {
        AssertUtil.notNull(attestationObject, "attestationObject must not be null");
        return JacksonUtil.binaryValue(cborConverter.readTree(attestationObject).get("authData"));
    }

    /**
     * Extract attestation statement byte array from a attestationObject byte array.
     *
     * @param attestationObject the attestationObject byte array
     * @return the extracted attestation statement byte array
     */
    public @NonNull byte[] extractAttestationStatement(@NonNull byte[] attestationObject) {
        AssertUtil.notNull(attestationObject, "attestationObject must not be null");
        return cborConverter.writeValueAsBytes(cborConverter.readTree(attestationObject).get("attStmt"));
    }


}
