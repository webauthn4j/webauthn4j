package com.webauthn4j.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum ClientDataType {
    CREATE("webauthn.create"),
    GET("webauthn.get");

    private String value;

    ClientDataType(String value){
        this.value = value;
    }

    @JsonCreator
    public static ClientDataType create(String value){
        switch (value){
            case "webauthn.create":
                return CREATE;
            case "webauthn.get":
                return GET;
            default:
                throw new IllegalArgumentException();
        }
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
