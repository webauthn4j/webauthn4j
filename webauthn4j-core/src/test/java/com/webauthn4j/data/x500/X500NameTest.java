/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.data.x500;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class X500NameTest {

    @Test
    void constructor_test() {
        assertThat(new X500Name().size()).isEqualTo(0);
    }

    @Test
    void equals_hashCode_test() {
        X500Name nameA = new X500Name("2.23.133.2.3=#0c0b69643a3030303230303030,2.23.133.2.2=#0c03535054,2.23.133.2.1=#0c0b69643a3439344535343433");
        X500Name nameB = new X500Name("2.23.133.2.3=#0c0b69643a3030303230303030,2.23.133.2.2=#0c03535054,2.23.133.2.1=#0c0b69643a3439344535343433");

        assertThat(nameA).isEqualTo(nameB);
        assertThat(nameA).hasSameHashCodeAs(nameB);
    }

}