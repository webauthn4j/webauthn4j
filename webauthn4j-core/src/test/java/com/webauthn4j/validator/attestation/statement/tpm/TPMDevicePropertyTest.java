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

package com.webauthn4j.validator.attestation.statement.tpm;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

public class TPMDevicePropertyTest {

    @Test
    public void getter_test() {
        TPMDeviceProperty tpmDeviceProperty = new TPMDeviceProperty("manufacturer", "partNumber", "firmwareVersion");

        assertAll(
                () -> assertThat(tpmDeviceProperty.getManufacturer()).isEqualTo("manufacturer"),
                () -> assertThat(tpmDeviceProperty.getPartNumber()).isEqualTo("partNumber"),
                () -> assertThat(tpmDeviceProperty.getFirmwareVersion()).isEqualTo("firmwareVersion")
        );
    }

    @Test
    public void equals_hashCode_test() {
        TPMDeviceProperty instanceA = new TPMDeviceProperty("manufacturer", "partNumber", "firmwareVersion");
        TPMDeviceProperty instanceB = new TPMDeviceProperty("manufacturer", "partNumber", "firmwareVersion");

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}