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
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.UserVerificationMethodExtensionAuthenticatorOutput;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.BIT_ED;
import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.BIT_UP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for AuthenticatorDataConverter
 */
@SuppressWarnings("ConstantConditions")
class AuthenticatorDataConverterTest {

    // Common test data
    private static final String BASIC_AUTH_DATA = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABRQ";
    private static final String APPLE_APP_ATTEST_DATA = "MGACygVeBsWIpS7GqlSC9TaOAq8wh7Hp0wnQQMr12VpAAAAAAQ";
    private static final String ATTESTED_CREDENTIAL_DATA = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAARlUOS1SqR0CfmpUat2wTATEAIHEiziyGohCFUc_hJJZGdtSu9ThnEb74K6NZC3U-KbwgpQECAyYgASFYICw4xPmHIvquDRz2KUzyyQlZFhZMbi-mc_YylL1o55jPIlggGQI5ESYAOfR8QM6quTQSoyhjZET806A3yOoCUe2AWJE";
    private static final String EXTRACTED_ATTESTED_CREDENTIAL_DATA = "VQ5LVKpHQJ-alRq3bBMBMQAgcSLOLIaiEIVRz-EklkZ21K71OGcRvvgro1kLdT4pvCClAQIDJiABIVggLDjE-Yci-q4NHPYpTPLJCVkWFkxuL6Zz9jKUvWjnmM8iWCAZAjkRJgA59HxAzqq5NBKjKGNkRPzToDfI6gJR7YBYkQ";

    private ObjectConverter objectConverter;
    private AuthenticatorDataConverter target;

    @BeforeEach
    void setUp() {
        objectConverter = new ObjectConverter();
        target = new AuthenticatorDataConverter(objectConverter);
    }

    @Nested
    class ConversionTests {
        @Test
        void shouldConvertBase64UrlToAuthenticatorData() {
            // Given
            byte[] input = Base64UrlUtil.decode(BASIC_AUTH_DATA);

            // When
            AuthenticatorData<RegistrationExtensionAuthenticatorOutput> result = target.convert(input);

            // Then
            assertThat(result.getRpIdHash()).isNotNull();
            assertThat(result.getRpIdHash()).hasSize(32);
            assertThat(result.getFlags()).isEqualTo(BIT_UP);
            assertThat(result.getSignCount()).isEqualTo(325);
            assertThat(result.getAttestedCredentialData()).isNull();
            assertThat(result.getExtensions().getKeys()).isEmpty();
        }

        @Test
        void shouldHandleAppleAppAttestAuthenticatorData() {
            // Given
            byte[] authenticatorDataBytes = Base64UrlUtil.decode(APPLE_APP_ATTEST_DATA);
            
            // When
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = target.convert(authenticatorDataBytes);
            
            // Then
            assertThat(authenticatorData.getAttestedCredentialData()).isNull();
        }

        @Test
        void shouldSerializeAndDeserializeCorrectly() {
            // Given
            byte[] rpIdHash = new byte[32];
            byte flags = BIT_ED;
            AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
            builder.setUvm(new UvmEntries());
            AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData =
                    new AuthenticatorData<>(rpIdHash, flags, 0, builder.build());

            // When
            byte[] serialized = target.convert(authenticatorData);
            AuthenticatorData<RegistrationExtensionAuthenticatorOutput> result = target.convert(serialized);

            // Then
            assertThat(result.getRpIdHash()).isNotNull();
            assertThat(result.getRpIdHash()).hasSize(32);
            assertThat(result.getFlags()).isEqualTo(BIT_ED);
            assertThat(result.getSignCount()).isZero();
            assertThat(result.getAttestedCredentialData()).isNull();
            assertThat(result.getExtensions().getKeys()).contains(UserVerificationMethodExtensionAuthenticatorOutput.ID);
        }
    }

    @Nested
    class ErrorHandlingTests {
        @Test
        void shouldThrowExceptionWhenDataIsTooShort() {
            // Given
            byte[] input = Base64UrlUtil.decode("SZYN5YgOjGh0NBcP");  // Too short input

            // When/Then
            assertThrows(DataConversionException.class, () -> target.convert(input));
        }

        @Test
        void shouldThrowExceptionWhenDeserializingDataWithSurplusBytes() {
            // Given
            byte[] data = Base64UrlUtil.decode(BASIC_AUTH_DATA);
            byte[] bytes = Arrays.copyOf(data, data.length + 1);  // Add extra byte
            
            // When/Then
            assertThrows(DataConversionException.class, () -> target.convert(bytes));
        }
    }

    @Nested
    class ExtensionTests {
        @Test
        void shouldHandleEmptyByteBufferWhenConvertingToExtensions() {
            // Given
            ByteBuffer emptyBuffer = ByteBuffer.allocate(0);
            
            // When
            AuthenticationExtensionsAuthenticatorOutputs<?> extensions = target.convertToExtensions(emptyBuffer);
            
            // Then
            assertThat(extensions.getKeys()).isEmpty();
        }

        @Test
        void shouldHandleCborNullByteBufferWhenConvertingToExtensions() {
            // Given
            byte[] data = new byte[]{(byte) 0xF6};  // CBOR encoding for null
            
            // When
            AuthenticationExtensionsAuthenticatorOutputs<?> extensions = target.convertToExtensions(ByteBuffer.wrap(data));
            
            // Then
            assertThat(extensions).isNull();
        }
    }

    @Nested
    class ExtractionTests {
        @Test
        void shouldExtractAttestedCredentialDataFromAuthenticatorData() {
            // Given
            byte[] authenticatorData = Base64UrlUtil.decode(ATTESTED_CREDENTIAL_DATA);
            
            // When
            byte[] result = target.extractAttestedCredentialData(authenticatorData);

            // Then
            assertThat(result).isEqualTo(Base64UrlUtil.decode(EXTRACTED_ATTESTED_CREDENTIAL_DATA));
        }

        @Test
        void shouldExtractSignCountFromAuthenticatorData() {
            // Given
            byte[] authenticatorData = Base64UrlUtil.decode(ATTESTED_CREDENTIAL_DATA);
            
            // When
            long signCount = target.extractSignCount(authenticatorData);

            // Then
            assertThat(signCount).isEqualTo(70);
        }
    }
}
