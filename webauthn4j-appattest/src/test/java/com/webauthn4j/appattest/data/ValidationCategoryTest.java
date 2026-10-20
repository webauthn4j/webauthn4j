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

package com.webauthn4j.appattest.data;

import com.webauthn4j.appattest.DeviceCheckManager;
import com.webauthn4j.appattest.data.extension.AppleValidationCategory01ExtensionAuthenticatorOutput;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.exc.MismatchedInputException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ValidationCategoryTest {

    private final ObjectConverter converter = DeviceCheckManager.createObjectConverter();

    @Test
    void shouldHaveValueSemanticsAndPreserveUnknownCategories() {
        ValidationCategory value = ValidationCategory.create(11);
        assertThat(value.getValue()).isEqualTo(11);
        assertThat(value).isEqualTo(ValidationCategory.create(11));
        assertThat(value.hashCode()).isEqualTo(ValidationCategory.create(11).hashCode());
        assertThat(value).isNotEqualTo(ValidationCategory.OTHER);
        assertThat(value.toString()).isEqualTo("11");
        assertThat(ValidationCategory.create(3)).isEqualTo(ValidationCategory.DEVELOPMENT);
    }

    @Test
    void shouldRejectValuesOutsideUnsigned32BitRange() {
        assertThatThrownBy(() -> ValidationCategory.create(-1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ValidationCategory.create(0x1_0000_0000L)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRoundTripAsFourLittleEndianBytes() {
        Map<Long, String> cases = Map.of(
                0L, "4400000000",
                3L, "4403000000",
                11L, "440B000000",
                0x0102_0304L, "4404030201",
                0x8000_0000L, "4400000080",
                0xffff_ffffL, "44FFFFFFFF");
        cases.forEach((number, hex) -> {
            ValidationCategory category = ValidationCategory.create(number);
            byte[] bytes = HexUtil.decode(hex);
            assertThat(converter.getCborMapper().writeValueAsBytes(category)).isEqualTo(bytes);
            assertThat(converter.getCborMapper().readValue(bytes, ValidationCategory.class)).isEqualTo(category);
        });
    }

    @Test
    void shouldRejectIncorrectWireTypeOrLength() {
        for (String hex : new String[]{"03", "F5", "684177414141413D3D", "40", "43030000", "450300000000"}) {
            assertThatThrownBy(() -> converter.getCborMapper().readValue(HexUtil.decode(hex), ValidationCategory.class))
                    .isInstanceOf(MismatchedInputException.class);
        }
    }

    @Test
    void shouldPreserveUnknownUnsignedCategoryInExtensionRoundTrip() {
        ValidationCategory category = ValidationCategory.create(0xffff_ffffL);
        byte[] bytes = converter.getCborMapper().writeValueAsBytes(
                TestDataUtil.createAppAttestAuthenticatorExtensions("1", category));
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> outputs = converter.getCborMapper()
                .readValue(bytes, new TypeReference<AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput>>() {});

        assertThat(outputs.getExtension(AppleValidationCategory01ExtensionAuthenticatorOutput.class).getValidationCategory())
                .isEqualTo(category);
        assertThat(converter.getCborMapper().writeValueAsBytes(outputs)).isEqualTo(bytes);
    }
}
