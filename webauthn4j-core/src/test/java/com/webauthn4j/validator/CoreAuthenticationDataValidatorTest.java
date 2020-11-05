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

package com.webauthn4j.validator;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CoreAuthenticationDataValidatorTest {

    @Test
    void constructor_test() {
        CoreAuthenticationDataValidator coreAuthenticationDataValidator = new CoreAuthenticationDataValidator();
        assertThat(coreAuthenticationDataValidator).isInstanceOf(CoreAuthenticationDataValidator.class);
    }

    @Test
    void getter_setter_test() {
        CoreAuthenticationDataValidator coreAuthenticationDataValidator = new CoreAuthenticationDataValidator();
        CoreMaliciousCounterValueHandler coreMaliciousCounterValueHandler = new DefaultCoreMaliciousCounterValueHandler();
        coreAuthenticationDataValidator.setMaliciousCounterValueHandler(coreMaliciousCounterValueHandler);
        assertThat(coreAuthenticationDataValidator.getMaliciousCounterValueHandler()).isEqualTo(coreMaliciousCounterValueHandler);
    }

}