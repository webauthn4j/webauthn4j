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

import java.util.Objects;

public class TPMDeviceProperty {

    private String manufacturer;
    private String partNumber;
    private String firmwareVersion;

    public TPMDeviceProperty(String manufacturer, String partNumber, String firmwareVersion) {
        this.manufacturer = manufacturer;
        this.partNumber = partNumber;
        this.firmwareVersion = firmwareVersion;
    }

    public String getManufacturer() {
        return manufacturer;
    }

    public String getPartNumber() {
        return partNumber;
    }

    public String getFirmwareVersion() {
        return firmwareVersion;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TPMDeviceProperty that = (TPMDeviceProperty) o;
        return Objects.equals(manufacturer, that.manufacturer) &&
                Objects.equals(partNumber, that.partNumber) &&
                Objects.equals(firmwareVersion, that.firmwareVersion);
    }

    @Override
    public int hashCode() {

        return Objects.hash(manufacturer, partNumber, firmwareVersion);
    }
}
