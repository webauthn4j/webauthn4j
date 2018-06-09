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

package com.webauthn4j.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum TokenBindingStatus {
    PRESENT("present"),
    SUPPORTED("supported"),
    NOT_SUPPORTED("not-supported");

    private final String value;

    TokenBindingStatus(String value) {
        this.value = value;
    }

    @JsonCreator
    public static TokenBindingStatus create(String value) {
        switch (value) {
            case "present":
                return PRESENT;
            case "supported":
                return SUPPORTED;
            case "not-supported":
                return NOT_SUPPORTED;
            default:
                throw new IllegalArgumentException();
        }
    }

    @JsonValue
    public String getValue() {
        return this.value;
    }
}
