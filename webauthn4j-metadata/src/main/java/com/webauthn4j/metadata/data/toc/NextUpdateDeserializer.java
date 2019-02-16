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

package com.webauthn4j.metadata.data.toc;

import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;

import java.time.format.DateTimeFormatterBuilder;
import java.time.format.SignStyle;

import static java.time.temporal.ChronoField.*;

public class NextUpdateDeserializer extends LocalDateDeserializer {
    public NextUpdateDeserializer() {
        super(new DateTimeFormatterBuilder()
                .appendValue(YEAR, 4, 10, SignStyle.EXCEEDS_PAD)
                .appendLiteral('-')
                .appendValue(MONTH_OF_YEAR, 1,2, SignStyle.NOT_NEGATIVE)
                .appendLiteral('-')
                .appendValue(DAY_OF_MONTH, 1, 2, SignStyle.NOT_NEGATIVE).toFormatter());
    }
}
