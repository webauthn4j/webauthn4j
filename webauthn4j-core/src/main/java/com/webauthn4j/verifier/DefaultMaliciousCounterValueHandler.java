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

import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.exception.MaliciousCounterValueException;
import org.jetbrains.annotations.NotNull;

/**
 * Default implementation of {@link MaliciousCounterValueHandler} that throws {@link MaliciousCounterValueException}
 * when a malicious counter value is detected.
 * <p>
 * This is the standard security-focused implementation that follows the strict requirements
 * of the WebAuthn specification by treating any suspicious counter behavior as a security violation
 * and halting the authentication process immediately.
 * <p>
 * Applications that need more lenient handling or want to implement additional logic
 * should provide their own implementation of {@link MaliciousCounterValueHandler}.
 */
class DefaultMaliciousCounterValueHandler implements MaliciousCounterValueHandler {


    // ~ Methods
    // ========================================================================================================

    /**
     * Handles a detected malicious counter value by throwing a {@link MaliciousCounterValueException}.
     * <p>
     * This implementation follows a strict security approach by immediately terminating
     * the authentication process when a suspicious counter value is detected.
     *
     * @param authenticationObject the authentication object containing the detected malicious counter value
     * @throws MaliciousCounterValueException always thrown to indicate the detection of a malicious counter value
     */
    @Override
    public void maliciousCounterValueDetected(@NotNull AuthenticationObject authenticationObject) {
        AssertUtil.notNull(authenticationObject, "authenticationObject must not be null");
        throw new MaliciousCounterValueException("Malicious counter value is detected. Cloned authenticators exist in parallel.");
    }
}
