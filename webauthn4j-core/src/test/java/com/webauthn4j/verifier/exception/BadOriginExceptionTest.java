/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.verifier.exception;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.OriginPredicate;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class BadOriginExceptionTest {

    private final RuntimeException cause = new RuntimeException();
    private final Set<Origin> allowedOrigins = Collections.singleton(new Origin("https://example.com"));
    private final OriginPredicate expected = new OriginPredicate() {
        @Override
        public boolean test(Origin origin) {
            return allowedOrigins.contains(origin);
        }

        @Override
        public String toString() {
            return "TestOriginPredicate{origins=" + allowedOrigins + "}";
        }
    };
    private final Origin actual = new Origin("https://example.org");

    @Test
    void test() {
        BadOriginException exception1 = new BadOriginException("dummy", expected, actual, cause);
        BadOriginException exception2 = new BadOriginException("dummy", expected, actual);
        BadOriginException exception3 = new BadOriginException("dummy", actual);
        BadOriginException exception4 = new BadOriginException("dummy", cause);
        BadOriginException exception5 = new BadOriginException("dummy");
        BadOriginException exception6 = new BadOriginException(cause);

        assertAll(
                () -> assertThat(exception1.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception1.getExpected()).isEqualTo(expected),
                () -> assertThat(exception1.getActual()).isEqualTo(actual),
                () -> assertThat(exception1.getCause()).isEqualTo(cause),

                () -> assertThat(exception2.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception2.getExpected()).isEqualTo(expected),
                () -> assertThat(exception2.getActual()).isEqualTo(actual),
                () -> assertThat(exception2.getCause()).isNull(),

                () -> assertThat(exception3.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception3.getExpected()).isNull(),
                () -> assertThat(exception3.getActual()).isEqualTo(actual),
                () -> assertThat(exception3.getCause()).isNull(),

                () -> assertThat(exception4.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception4.getExpected()).isNull(),
                () -> assertThat(exception4.getActual()).isNull(),
                () -> assertThat(exception4.getCause()).isEqualTo(cause),

                () -> assertThat(exception5.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception5.getExpected()).isNull(),
                () -> assertThat(exception5.getActual()).isNull(),
                () -> assertThat(exception5.getCause()).isNull(),

                () -> assertThat(exception6.getMessage()).isEqualTo(cause.toString()),
                () -> assertThat(exception6.getExpected()).isNull(),
                () -> assertThat(exception6.getActual()).isNull(),
                () -> assertThat(exception6.getCause()).isEqualTo(cause)
        );
    }
}
