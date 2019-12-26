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

package com.webauthn4j.converter.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.util.AssertUtil;

import java.io.Serializable;

/**
 * A set of object converter classes
 */
public class ObjectConverter implements Serializable {

    private JsonConverter jsonConverter;
    private CborConverter cborConverter;

    public ObjectConverter(ObjectMapper jsonMapper, ObjectMapper cborMapper){
        AssertUtil.notNull(jsonMapper, "jsonMapper must not be null");
        AssertUtil.notNull(cborMapper, "cborMapper must not be null");
        AssertUtil.isTrue(!(jsonMapper.getFactory() instanceof CBORFactory), "factory of jsonMapper must be JsonFactory.");
        AssertUtil.isTrue(cborMapper.getFactory() instanceof CBORFactory, "factory of cborMapper must be CBORFactory.");

        this.jsonConverter = new JsonConverter(jsonMapper, cborMapper);
        this.cborConverter = jsonConverter.getCborConverter();
    }

    public ObjectConverter(){
        this.jsonConverter = new JsonConverter();
        this.cborConverter = jsonConverter.getCborConverter();
    }

    /**
     * @deprecated
     */
    @Deprecated
    public ObjectConverter(JsonConverter jsonConverter, CborConverter cborConverter) {
        this.jsonConverter = jsonConverter;
        this.cborConverter = cborConverter;
    }

    public JsonConverter getJsonConverter() {
        return jsonConverter;
    }

    public CborConverter getCborConverter() {
        return cborConverter;
    }
}
