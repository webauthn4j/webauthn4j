/*
 * Copyright 2018 the original author or authors.
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

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;

import java.nio.charset.StandardCharsets;

/**
 * Converter for {@link CollectedClientData}
 */
public class CollectedClientDataConverter {

    //~ Instance fields
    // ================================================================================================
    private JsonConverter jsonConverter;

    //~ Constructors
    // ================================================================================================

    public CollectedClientDataConverter(ObjectConverter objectConverter) {
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.jsonConverter = objectConverter.getJsonConverter();
    }

    /**
     * @deprecated
     */
    @Deprecated
    public CollectedClientDataConverter(JsonConverter jsonConverter) {
        AssertUtil.notNull(jsonConverter, "jsonConverter must not be null");
        this.jsonConverter = jsonConverter;
    }


    //~ Methods
    // ================================================================================================


    /**
     * Converts from a base64url {@link String} to {@link CollectedClientData}.
     *
     * @param base64UrlString the source byte array to convert
     * @return the converted object
     */
    public CollectedClientData convert(String base64UrlString) {
        if (base64UrlString == null) {
            return null;
        }
        byte[] bytes = Base64UrlUtil.decode(base64UrlString);
        return convert(bytes);
    }

    /**
     * Converts from a byte array to {@link CollectedClientData}.
     *
     * @param source the source byte array to convert
     * @return the converted object
     */
    public CollectedClientData convert(byte[] source) {
        if (source == null) {
            return null;
        }
        String jsonString = new String(source, StandardCharsets.UTF_8);
        return jsonConverter.readValue(jsonString, CollectedClientData.class);
    }

    /**
     * Converts from a {@link CollectedClientData} to byte[].
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public byte[] convertToBytes(CollectedClientData source) {
        return jsonConverter.writeValueAsBytes(source);
    }

    /**
     * Converts from a {@link CollectedClientData} to base64 url {@link String}.
     *
     * @param source the source object to convert
     * @return the converted byte array
     */
    public String convertToBase64UrlString(CollectedClientData source) {
        byte[] bytes = convertToBytes(source);
        return Base64UrlUtil.encodeToString(bytes);
    }

}
