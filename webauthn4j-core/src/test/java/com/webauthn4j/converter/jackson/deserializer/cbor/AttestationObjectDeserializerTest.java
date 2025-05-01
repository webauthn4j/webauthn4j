/*
 * Copyright 2002-2018 the original author or authors.
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

package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Test for AttestationObjectDeserializer
 */
class AttestationObjectDeserializerTest {

    @SuppressWarnings("ConstantConditions")
    @Test
    void shouldDeserializeFIDOU2FAttestationObject() {
        ObjectConverter objectConverter = new ObjectConverter();
        CborConverter cborConverter = objectConverter.getCborConverter();

        //Given
        //noinspection SpellCheckingInspection
        String input = "v2hhdXRoRGF0YVi6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBAAAAAQAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv2ExYTJhMvZhMyZhNPZhNfZiLTEBYi0yWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGItM1ggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABhMQL_Z2F0dFN0bXS_Y3g1Y4FZAsswggLHMIIBr6ADAgECAhAg92PAQYOxBTfb6FBqIlDyMA0GCSqGSIb3DQEBCwUAMEoxEjAQBgNVBAoMCVNoYXJwTGFiLjE0MDIGA1UEAwwrc3ByaW5nLXNlY3VyaXR5LXdlYmF1dGhuIDJ0aWVyIHRlc3Qgcm9vdCBDQTAgFw0xODA1MjAwNzA5NTVaGA8yMTE4MDQyNjA3MDk1NVowfTELMAkGA1UEBhMCSlAxEjAQBgNVBAoMCVNoYXJwTGFiLjEgMB4GA1UECwwXQXR0ZXN0YXRpb24gQ2VydGlmaWNhdGUxODA2BgNVBAMML3dlYmF1dGhuNGogdGVzdCAydGllciBhdXRoZW50aWNhdG9yIGF0dGVzdGF0aW9uMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYOdbrImOAgjZN3Xb8unfHHhJDINdIykolt-ypGxcrop4KwbujX2zvoRGZvdoQ9mu-rwjAZt4H3SMsSxPvB8z8KM_MD0wDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFNDrzrNaaa7sdMR9uzsvO8OohdjhMA0GCSqGSIb3DQEBCwUAA4IBAQCtHcryqNSHDyszLtIByc5AzPam37vl0AVchb0qOxLFbmdUu4Nhzk-87YdA_VZuvVLInsIGaCwkP3rdqGAFY1HllglMnmWIoG2sKjmT3vpJydlDODaha9F_fVG7cq2i5Zx2KMTeUtuTkNdZDjocUUHXYVShgNnggoUWkVeLBG1ckzK1tAkbUwyChWMv4PDmIUBNv6DwkYI9oBSCSAJHpUzyxzMvCRbAFAICwPl3g-SQEUeiNlnzJuGXHnHxu-DB6JD2b0hPeYD6XxWPuI0Pq1G_6hGQmsNv3SF2ye2y_HOKnw3L-fzRHl5ksOdVZbpy9xXzTdIBUpvTmFuwcBo4HwRMY3NpZ1ggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD_Y2ZtdGhmaWRvLXUyZv8";

        //When
        AttestationObject result = cborConverter.readValue(Base64UrlUtil.decode(input), AttestationObject.class);

        //Then
        assertAll(
                () -> assertThat(result).isNotNull(),
                () -> assertThat(result.getAuthenticatorData()).isNotNull(),
                () -> assertThat(result.getFormat()).isEqualTo("fido-u2f"),
                () -> assertThat(result.getAttestationStatement()).isNotNull(),
                () -> assertThat(result.getAttestationStatement()).isInstanceOf(FIDOU2FAttestationStatement.class)
        );
    }

    @Test
    void shouldThrowExceptionForInvalidInput() {
        ObjectConverter objectConverter = new ObjectConverter();
        CborConverter cborConverter = objectConverter.getCborConverter();

        //Given
        byte[] invalidCbor = new byte[]{0x00, 0x01, 0x02}; // Invalid CBOR data

        //Then
        assertThatThrownBy(() -> cborConverter.readValue(invalidCbor, AttestationObject.class))
                .isInstanceOf(DataConversionException.class);
    }

    @Test
    void shouldThrowExceptionForNullInput() {
        ObjectConverter objectConverter = new ObjectConverter();
        CborConverter cborConverter = objectConverter.getCborConverter();

        //Then
        assertThatThrownBy(() -> cborConverter.readValue((byte[])null, AttestationObject.class))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
