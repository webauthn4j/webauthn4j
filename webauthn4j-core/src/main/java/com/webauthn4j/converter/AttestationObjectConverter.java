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

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.JacksonUtil;

/**
 * Converter for {@link AttestationObject}
 */
public class AttestationObjectConverter {

    // ~ Instance fields
    // ================================================================================================
    private CborConverter cborConverter = CborConverter.INSTANCE;

    // ~ Constructors
    // ================================================================================================

    public AttestationObjectConverter() {
    }

    // ~ Methods
    // ================================================================================================

    /**
     * Converts from a base64url {@link String} to {@link AttestationObject}.
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    public AttestationObject convert(String source) {
        if (source == null) {
            return null;
        }
        byte[] value = Base64UrlUtil.decode(source);
        return convert(value);
    }

    /**
     * Converts from a byte array to {@link AttestationObject}.
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    public AttestationObject convert(byte[] source) {
        if (source == null) {
            return null;
        }
        return cborConverter.readValue(source, AttestationObject.class);
    }

    /**
     * Converts from a {@link AttestationObject} to byte[].
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public byte[] convertToBytes(AttestationObject source) {
        return cborConverter.writeValueAsBytes(source);
    }

    /**
     * Converts from a {@link AttestationObject} to {@link String}.
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public String convertToBase64urlString(AttestationObject source) {
        byte[] bytes = convertToBytes(source);
        return Base64UrlUtil.encodeToString(bytes);
    }

    /**
     * Extract authenticatorData byte array from a attestationObject byte array.
     *
     * @param attestationObject the authenticatorData byte array
     * @return the extracted authenticatorData byte array
     */
    public byte[] extractAuthenticatorData(byte[] attestationObject) {
        return JacksonUtil.binaryValue(cborConverter.readTree(attestationObject).get("authData"));
    }


}
