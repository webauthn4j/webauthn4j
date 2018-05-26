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
