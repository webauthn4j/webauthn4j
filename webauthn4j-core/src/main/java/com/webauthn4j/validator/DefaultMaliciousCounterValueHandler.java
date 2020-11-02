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

package com.webauthn4j.validator;

import com.webauthn4j.validator.exception.MaliciousCounterValueException;
import org.checkerframework.checker.nullness.qual.NonNull;

/**
 * Default implementation of {@link MaliciousCounterValueHandler} that throws {@link MaliciousCounterValueException}
 */
class DefaultMaliciousCounterValueHandler implements MaliciousCounterValueHandler {


    // ~ Methods
    // ========================================================================================================

    @Override
    public void maliciousCounterValueDetected(@NonNull AuthenticationObject authenticationObject) {
        throw new MaliciousCounterValueException("Malicious counter value is detected. Cloned authenticators exist in parallel.");
    }
}
