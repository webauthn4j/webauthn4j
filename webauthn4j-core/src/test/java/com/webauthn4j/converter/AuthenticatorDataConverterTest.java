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
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.BIT_ED;
import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.BIT_UP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for AuthenticatorDataConverter
 */
@SuppressWarnings("ConstantConditions")
class AuthenticatorDataConverterTest {

    // Common test data
    private static final String BASIC_AUTHENTICATOR_DATA = "49960DE5880E8C687434170F6476605B8FE4AEB9A28632C7995CF3BA831D97630100000145";
    private static final String APPLE_APP_ATTEST_DATA = "306002CA055E06C588A52EC6AA5482F5368E02AF3087B1E9D309D040CAF5D95A4000000001";
    private static final String AUTHENTICATOR_DATA = "49960DE5880E8C687434170F6476605B8FE4AEB9A28632C7995CF3BA831D97634100000046550E4B54AA47409F9A951AB76C13013100207122CE2C86A2108551CFE124964676D4AEF5386711BEF82BA3590B753E29BC20A50102032620012158202C38C4F98722FAAE0D1CF6294CF2C9095916164C6E2FA673F63294BD68E798CF22582019023911260039F47C40CEAAB93412A328636444FCD3A037C8EA0251ED805891";
    private static final String EXTRACTED_ATTESTED_CREDENTIAL_DATA = "550E4B54AA47409F9A951AB76C13013100207122CE2C86A2108551CFE124964676D4AEF5386711BEF82BA3590B753E29BC20A50102032620012158202C38C4F98722FAAE0D1CF6294CF2C9095916164C6E2FA673F63294BD68E798CF22582019023911260039F47C40CEAAB93412A328636444FCD3A037C8EA0251ED805891";
    private static final String AUTHENTICATOR_DATA_WITH_EXTENSION = "49960DE5880E8C687434170F6476605B8FE4AEB9A28632C7995CF3BA831D9763C5000000A295442B2EF15E4DEFB270EFB106FACB4E0024E256FFBC2076ACF614753F25DF5DE7B6597C61B3305770C6330306457346B1E600C03030A5010203262001215820CE747EDE833BBAC106014F16DF34BFD22E1162AA028E9C763AE2F0517EC4ED2422582099AE06E6F6B99286E838F89F4D495FBED88B6DEF81E4A0602E1DBE9562B9ECC8A16B6372656450726F7465637402";
    private static final String IOS27_APPLE_EXTENSIONS = "A2776170706C655F62756E646C655F76657273696F6E5F30316131781C6170706C655F76616C69646174696F6E5F63617465676F72795F30314401000000";
    private static final String IOS27_APPLE_APP_ATTEST_ATTESTATION_DATA = "F4466D68F91EB6C10620CB7E63C7283244685EE1D6467B54160E753172057F034000000000617070617474657374000000000000000020CE0498F58483FBB4DA0D7B2C63A5A538F552D4ADCB9A4FA916195C49613E655DA50102032620012158204332544ACF323DB774443CAAF339F56E7E95C724FAC2C14259F365E2445650B2225820B5FB285BCF549BCB60594412E7682A2427EEADA9FB52DFED0B1AB17ED09FA9BD" + IOS27_APPLE_EXTENSIONS;
    private static final String IOS27_APPLE_APP_ATTEST_ASSERTION_DATA = APPLE_APP_ATTEST_DATA + IOS27_APPLE_EXTENSIONS;

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
        void shouldConvertToAuthenticatorData() {
            // Given
            byte[] input = HexUtil.decode(BASIC_AUTHENTICATOR_DATA);

            // When
            AuthenticatorData<RegistrationExtensionAuthenticatorOutput> result = target.convert(input);

            // Then
            assertThat(result.getRpIdHash()).isNotNull().hasSize(32);
            assertThat(result.getFlags()).isEqualTo(BIT_UP);
            assertThat(result.getSignCount()).isEqualTo(325);
            assertThat(result.getAttestedCredentialData()).isNull();
            assertThat(result.getExtensions().getKeys()).isEmpty();
        }

        @Test
        void shouldConvertFromAuthenticatorDataWithExtensionBytesToAuthenticatorData(){
            assertThatCode(()->target.convert(HexUtil.decode(AUTHENTICATOR_DATA_WITH_EXTENSION))).doesNotThrowAnyException();
        }

        @Test
        void shouldHandleAppleAppAttestAuthenticatorData() {
            // Given
            byte[] authenticatorDataBytes = HexUtil.decode(APPLE_APP_ATTEST_DATA);
            
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
            assertThat(result.getRpIdHash()).isNotNull().hasSize(32);
            assertThat(result.getFlags()).isEqualTo(BIT_ED);
            assertThat(result.getSignCount()).isZero();
            assertThat(result.getAttestedCredentialData()).isNull();
            assertThat(result.getExtensions().getKeys()).contains(UserVerificationMethodExtensionAuthenticatorOutput.ID);
        }
    }

    @Nested
    class AppleAppAttestIOS27Tests {
        @Test
        void shouldParseAttestationWithExtensionsWhenEDFlagIsNotSet() {
            byte[] input = HexUtil.decode(IOS27_APPLE_APP_ATTEST_ATTESTATION_DATA);

            AuthenticatorData<RegistrationExtensionAuthenticatorOutput> result = target.convert(input);

            assertThat(result.getFlags()).isEqualTo(AuthenticatorData.BIT_AT);
            assertThat(result.getSignCount()).isZero();
            assertThat(result.getAttestedCredentialData()).isNotNull();
            assertThat(result.getAttestedCredentialData().getAaguid().getBytes()).isEqualTo("appattest\0\0\0\0\0\0\0".getBytes());
            assertThat(result.getAttestedCredentialData().getCredentialId()).isEqualTo(HexUtil.decode("CE0498F58483FBB4DA0D7B2C63A5A538F552D4ADCB9A4FA916195C49613E655D"));
            assertThat(result.getExtensions().getKeys()).containsExactlyInAnyOrder("apple_bundle_version_01", "apple_validation_category_01");
            assertThat(result.getExtensions().getValue("apple_bundle_version_01")).isEqualTo("1");
            assertThat(result.getExtensions().getValue("apple_validation_category_01")).isEqualTo(HexUtil.decode("01000000"));
        }

        @Test
        void shouldParseAssertionWithExtensionsWhenATFlagIsSetWithoutAttestedCredentialData() {
            byte[] input = HexUtil.decode(IOS27_APPLE_APP_ATTEST_ASSERTION_DATA);

            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> result = target.convert(input);

            assertThat(result.getFlags()).isEqualTo(AuthenticatorData.BIT_AT);
            assertThat(result.getSignCount()).isEqualTo(1);
            assertThat(result.getAttestedCredentialData()).isNull();
            assertThat(result.getExtensions().getKeys()).containsExactlyInAnyOrder("apple_bundle_version_01", "apple_validation_category_01");
        }

        @Test
        void shouldParseAssertionWithExtensionsWhenFlagsAreClear() {
            byte[] input = HexUtil.decode(IOS27_APPLE_APP_ATTEST_ASSERTION_DATA);
            input[32] = 0;

            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> result = target.convert(input);

            assertThat(result.getAttestedCredentialData()).isNull();
            assertThat(result.getExtensions().getKeys()).containsExactlyInAnyOrder("apple_bundle_version_01", "apple_validation_category_01");
        }

        @Test
        void shouldSerializeBackToOriginalBytes() {
            byte[] attestation = HexUtil.decode(IOS27_APPLE_APP_ATTEST_ATTESTATION_DATA);
            byte[] assertion = HexUtil.decode(IOS27_APPLE_APP_ATTEST_ASSERTION_DATA);

            byte[] reserializedAttestation = target.convert(target.<RegistrationExtensionAuthenticatorOutput>convert(attestation));
            byte[] reserializedAssertion = target.convert(target.<AuthenticationExtensionAuthenticatorOutput>convert(assertion));

            assertThat(reserializedAttestation).isEqualTo(attestation);
            assertThat(reserializedAssertion).isEqualTo(assertion);
        }

        @Test
        void shouldExtractAttestedCredentialDataAndSignCount() {
            byte[] input = HexUtil.decode(IOS27_APPLE_APP_ATTEST_ATTESTATION_DATA);

            byte[] attestedCredentialData = target.extractAttestedCredentialData(input);

            assertThat(new AttestedCredentialDataConverter(objectConverter).convert(attestedCredentialData).getCredentialId())
                    .isEqualTo(HexUtil.decode("CE0498F58483FBB4DA0D7B2C63A5A538F552D4ADCB9A4FA916195C49613E655D"));
            assertThat(target.extractSignCount(input)).isZero();
        }

        @Test
        void shouldRejectExtensionsFollowedBySurplusBytesWhenEDFlagIsNotSet() {
            byte[] data = HexUtil.decode(IOS27_APPLE_APP_ATTEST_ASSERTION_DATA);
            byte[] input = Arrays.copyOf(data, data.length + 1);

            assertThrows(DataConversionException.class, () -> target.convert(input));
        }

        @Test
        void shouldRejectTrailingCborNullWhenEDFlagIsNotSet() {
            byte[] input = HexUtil.decode(BASIC_AUTHENTICATOR_DATA + "F6");

            assertThrows(DataConversionException.class, () -> target.convert(input));
        }

        @Test
        void shouldRejectTrailingNonMapCborWhenEDFlagIsNotSet() {
            byte[] input = HexUtil.decode(BASIC_AUTHENTICATOR_DATA + "6141");

            assertThrows(DataConversionException.class, () -> target.convert(input));
        }

        @Test
        void shouldRejectMalformedAttestedCredentialDataWhenNoExtensionsFollow() {
            byte[] input = HexUtil.decode(APPLE_APP_ATTEST_DATA + "0102030405");

            assertThrows(DataConversionException.class, () -> target.convert(input));
        }

        @Test
        void shouldRejectTruncatedExtensionsWhenEDFlagIsNotSet() {
            byte[] data = HexUtil.decode(IOS27_APPLE_APP_ATTEST_ASSERTION_DATA);
            byte[] input = Arrays.copyOf(data, data.length - 1);

            assertThrows(DataConversionException.class, () -> target.convert(input));
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
            byte[] data = HexUtil.decode(BASIC_AUTHENTICATOR_DATA);
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
            byte[] authenticatorData = HexUtil.decode(AUTHENTICATOR_DATA);
            
            // When
            byte[] result = target.extractAttestedCredentialData(authenticatorData);

            // Then
            assertThat(result).isEqualTo(HexUtil.decode(EXTRACTED_ATTESTED_CREDENTIAL_DATA));
        }

        @Test
        void shouldExtractSignCountFromAuthenticatorData() {
            // Given
            byte[] authenticatorData = HexUtil.decode(AUTHENTICATOR_DATA);
            
            // When
            long signCount = target.extractSignCount(authenticatorData);

            // Then
            assertThat(signCount).isEqualTo(70);
        }
    }
}
