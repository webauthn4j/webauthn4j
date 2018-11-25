package com.webauthn4j.registry;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.jackson.WebAuthnModule;

/**
 * External processor registry
 *
 * ObjectMapper instance can be injected with this registry
 */
public class Registry {

    private ObjectMapper jsonMapper;
    private ObjectMapper cborMapper;

    // private ExtensionConverter;
    // private ExtensionValidator;

    public Registry(){
        jsonMapper = new ObjectMapper();
        jsonMapper.registerModule(new WebAuthnModule(this));
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        cborMapper = new ObjectMapper(new CBORFactory());
        cborMapper.registerModule(new WebAuthnModule(this));
        cborMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public Registry(ObjectMapper jsonMapper, ObjectMapper cborMapper) {
        this.jsonMapper = jsonMapper;
        this.cborMapper = cborMapper;
    }

    /**
     * Returns registered jsonMapper
     * @return jsonMapper
     */
    public ObjectMapper getJsonMapper() {
        return jsonMapper;
    }

    /**
     * Returns registered cborMapper
     * @return cborMapper
     */
    public ObjectMapper getCborMapper() {
        return cborMapper;
    }

}
