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

package com.webauthn4j.metadata.legacy.converter.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.webauthn4j.data.MatcherProtectionType;
import com.webauthn4j.metadata.legacy.data.statement.MatcherProtections;

import java.io.IOException;

@Deprecated
public class MatcherProtectionsSerializer extends StdSerializer<MatcherProtections> {
    public MatcherProtectionsSerializer() {
        super(MatcherProtections.class);
    }

    @Override
    public void serialize(MatcherProtections value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        long sum = value.stream().map(MatcherProtectionType::getValue).reduce(0, Integer::sum);
        gen.writeNumber(sum);
    }
}
