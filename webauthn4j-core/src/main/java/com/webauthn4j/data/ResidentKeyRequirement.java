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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

/**
 * This enumeration’s values describe the Relying Party's requirements for client-side discoverable credentials (formerly known as resident credentials or resident keys)
 * @see <a href="https://www.w3.org/TR/2019/WD-webauthn-2-20191126/#enum-residentKeyRequirement">
 * §5.4.6. Resident Key Requirement Enumeration (enum ResidentKeyRequirement)</a>
 */
public enum ResidentKeyRequirement {

    DISCOURAGED("discouraged"),
    PREFERRED("preferred"),
    REQUIRED("required");

    private String value;

    ResidentKeyRequirement(String value) {
        this.value = value;
    }

    public static ResidentKeyRequirement create(String value) {
        if (value == null) {
            return null;
        }
        switch (value) {
            case "discouraged":
                return DISCOURAGED;
            case "preferred":
                return PREFERRED;
            case "required":
                return REQUIRED;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static ResidentKeyRequirement deserialize(String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, ResidentKeyRequirement.class);
        }
    }

    @JsonValue
    public String getValue() {
        return value;
    }


}
