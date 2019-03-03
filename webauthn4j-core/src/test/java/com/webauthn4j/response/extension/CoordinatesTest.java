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

package com.webauthn4j.response.extension;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class CoordinatesTest {

    @Test
    void getter_test() {
        Coordinates instance = new Coordinates(
                12.34,
                23.45,
                34.56,
                4.5,
                5.6,
                7.8,
                8.9
        );

        assertAll(
                () -> assertThat(instance.getLatitude()).isEqualTo(12.34),
                () -> assertThat(instance.getLongitude()).isEqualTo(23.45),
                () -> assertThat(instance.getAltitude()).isEqualTo(34.56),
                () -> assertThat(instance.getAccuracy()).isEqualTo(4.5),
                () -> assertThat(instance.getAltitudeAccuracy()).isEqualTo(5.6),
                () -> assertThat(instance.getHeading()).isEqualTo(7.8),
                () -> assertThat(instance.getSpeed()).isEqualTo(8.9)
        );
    }

    @Test
    void equals_hashCode_test() {
        Coordinates instanceA = new Coordinates();
        Coordinates instanceB = new Coordinates();

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}
