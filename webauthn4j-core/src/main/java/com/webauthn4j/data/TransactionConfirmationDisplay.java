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

import com.webauthn4j.util.UnsignedNumberUtil;

import java.util.Arrays;
import java.util.Objects;

/**
 * The supported transaction confirmation display type(s).
 *
 * @see <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#transaction-confirmation-display-types">§3.5 Transaction Confirmation Display Types</a>
 */
public enum TransactionConfirmationDisplay {

    ANY(0x0001, "any"),
    PRIVILEGED_SOFTWARE(0x0002, "privileged_software"),
    TEE(0x0004, "tee"),
    HARDWARE(0x0008, "hardware"),
    REMOTE(0x0010, "remote");

    private static final String VALUE_OUT_OF_RANGE_TEMPLATE = "value %s is out of range";

    private final int value;
    private final String string;

    TransactionConfirmationDisplay(int value, String string) {
        this.value = value;
        this.string = string;
    }

    public static TransactionConfirmationDisplay create(String value) {
        return Arrays.stream(TransactionConfirmationDisplay.values()).filter(item -> Objects.equals(item.string, value))
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    public static TransactionConfirmationDisplay create(int value) {
        if (value > UnsignedNumberUtil.UNSIGNED_SHORT_MAX || value < 0) {
            throw new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value));
        }
        return Arrays.stream(TransactionConfirmationDisplay.values()).filter(item -> item.value == value)
                .findFirst().orElseThrow(()->new IllegalArgumentException(String.format(VALUE_OUT_OF_RANGE_TEMPLATE, value)));
    }

    public int getValue() {
        return value;
    }

    @Override
    public String toString(){
        return string;
    }


}
