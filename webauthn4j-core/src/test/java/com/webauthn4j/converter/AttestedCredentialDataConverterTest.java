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
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AttestedCredentialDataConverterTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final AttestedCredentialDataConverter target = new AttestedCredentialDataConverter(objectConverter);

    @Test
    void convert_test() {
        //Given
        //noinspection SpellCheckingInspection
        String input = "VQ5LVKpHQJ-alRq3bBMBMQAgcSLOLIaiEIVRz-EklkZ21K71OGcRvvgro1kLdT4pvCClAQIDJiABIVggLDjE-Yci-q4NHPYpTPLJCVkWFkxuL6Zz9jKUvWjnmM8iWCAZAjkRJgA59HxAzqq5NBKjKGNkRPzToDfI6gJR7YBYkQ";
        //When
        AttestedCredentialData attestedCredentialData = target.convert(Base64UrlUtil.decode(input));

        //noinspection ConstantConditions
        assertThat(attestedCredentialData.getAaguid().getBytes()).isEqualTo(Base64UrlUtil.decode("VQ5LVKpHQJ-alRq3bBMBMQ"));
        assertThat(attestedCredentialData.getCredentialId()).isEqualTo(Base64UrlUtil.decode("cSLOLIaiEIVRz-EklkZ21K71OGcRvvgro1kLdT4pvCA"));

    }

    @Test
    void convert_null_test(){
        assertThatThrownBy(()-> target.convert((AttestedCredentialData) null)).isInstanceOf(DataConversionException.class);
        assertThatThrownBy(()-> target.convert((ByteBuffer) null)).isInstanceOf(DataConversionException.class);
        assertThatThrownBy(()-> target.convert((byte[]) null)).isInstanceOf(DataConversionException.class);
    }

    @Test
    void extractCredentialId_test() {
        //Given
        //noinspection SpellCheckingInspection
        String input = "VQ5LVKpHQJ-alRq3bBMBMQAgcSLOLIaiEIVRz-EklkZ21K71OGcRvvgro1kLdT4pvCC_YTFhMmEzJmItMQFiLTJYICw4xPmHIvquDRz2KUzyyQlZFhZMbi-mc_YylL1o55jPYi0zWCAZAjkRJgA59HxAzqq5NBKjKGNkRPzToDfI6gJR7YBYkWExAv8";

        //When
        byte[] result = target.extractCredentialId(Base64UrlUtil.decode(input));

        assertThat(result).isEqualTo(Base64UrlUtil.decode("cSLOLIaiEIVRz-EklkZ21K71OGcRvvgro1kLdT4pvCA"));

    }

}
