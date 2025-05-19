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

package com.webauthn4j.verifier;

import org.jetbrains.annotations.NotNull;

/**
 * strategy interface to handle malicious counter value detection during authentication.
 * <p>
 * This interface is similar to {@link MaliciousCounterValueHandler} but works with 
 * {@link CoreAuthenticationObject} instead of {@link AuthenticationObject}
 * <p>
 * Implementations of this interface define strategies for handling suspicious counter
 * values, whether to throw an exception, log a warning, or take other mitigating actions.
 * <p>
 */
public interface CoreMaliciousCounterValueHandler {

    /**
     * Handles a detected malicious counter value during authentication.
     * <p>
     * This method is called when the authenticator's counter value is less than or equal to
     * the previously registered counter value, which may indicate a cloned authenticator or replay attack.
     *
     * @param authenticationObject the core authentication object containing the detected malicious counter value
     * @throws com.webauthn4j.verifier.exception.MaliciousCounterValueException if the implementation chooses to throw an exception
     */
    void maliciousCounterValueDetected(@NotNull CoreAuthenticationObject authenticationObject);
}
