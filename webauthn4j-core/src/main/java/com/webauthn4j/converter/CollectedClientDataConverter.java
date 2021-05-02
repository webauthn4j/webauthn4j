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
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.nio.charset.StandardCharsets;

/**
 * Converter for {@link CollectedClientData}
 */
public class CollectedClientDataConverter {

    //~ Instance fields
    // ================================================================================================
    private final JsonConverter jsonConverter;

    //~ Constructors
    // ================================================================================================

    public CollectedClientDataConverter(@NonNull ObjectConverter objectConverter) {
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.jsonConverter = objectConverter.getJsonConverter();
    }

    //~ Methods
    // ================================================================================================


    /**
     * Converts from a base64url {@link String} to {@link CollectedClientData}.
     *
     * @param base64UrlString the source byte array to convert
     * @return the converted object
     */
    public @Nullable CollectedClientData convert(@NonNull String base64UrlString) {
        try {
            AssertUtil.notNull(base64UrlString, "base64UrlString must not be null");
            byte[] bytes = Base64UrlUtil.decode(base64UrlString);
            return convert(bytes);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts from a byte array to {@link CollectedClientData}.
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    public @Nullable CollectedClientData convert(@NonNull byte[] source) {
        try {
            AssertUtil.notNull(source, "source must not be null");
            String jsonString = new String(source, StandardCharsets.UTF_8);
            return jsonConverter.readValue(jsonString, CollectedClientData.class);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts from a {@link CollectedClientData} to byte[].
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public @NonNull byte[] convertToBytes(@NonNull CollectedClientData source) {
        try {
            AssertUtil.notNull(source, "source must not be null");
            return jsonConverter.writeValueAsBytes(source);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts from a {@link CollectedClientData} to base64 url {@link String}.
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public @NonNull String convertToBase64UrlString(@NonNull CollectedClientData source) {
        try {
            byte[] bytes = convertToBytes(source);
            return Base64UrlUtil.encodeToString(bytes);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

}
