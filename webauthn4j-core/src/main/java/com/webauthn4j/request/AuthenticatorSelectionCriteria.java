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

package com.webauthn4j.request;

import java.io.Serializable;

public class AuthenticatorSelectionCriteria implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private AuthenticatorAttachment authenticatorAttachment;

    @SuppressWarnings("UnusedAssignment")
    private boolean requireResidentKey = false;
    @SuppressWarnings("UnusedAssignment")
    private UserVerificationRequirement userVerification = UserVerificationRequirement.PREFERRED;

    public AuthenticatorSelectionCriteria(AuthenticatorAttachment authenticatorAttachment, boolean requireResidentKey, UserVerificationRequirement userVerification) {
        this.authenticatorAttachment = authenticatorAttachment;
        this.requireResidentKey = requireResidentKey;
        this.userVerification = userVerification;
    }

    public AuthenticatorSelectionCriteria() {
    }

    public AuthenticatorAttachment getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }
}
