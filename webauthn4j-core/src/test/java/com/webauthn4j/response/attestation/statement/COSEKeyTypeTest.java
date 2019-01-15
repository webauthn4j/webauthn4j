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

package com.webauthn4j.response.attestation.statement;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class COSEKeyTypeTest {

    @Test
    public void create_test() throws InvalidFormatException {
        assertThat(COSEKeyType.create(0)).isEqualTo(COSEKeyType.RESERVED);
        assertThat(COSEKeyType.create(1)).isEqualTo(COSEKeyType.OKP);
        assertThat(COSEKeyType.create(2)).isEqualTo(COSEKeyType.EC2);
        assertThat(COSEKeyType.create(3)).isEqualTo(COSEKeyType.RSA);
        assertThat(COSEKeyType.create(4)).isEqualTo(COSEKeyType.SYMMETRIC);

        //noinspection ResultOfMethodCallIgnored
        assertThatThrownBy(() -> COSEKeyType.create(-1)).isInstanceOf(InvalidFormatException.class);
    }
}
