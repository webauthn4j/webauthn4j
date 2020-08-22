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

package com.webauthn4j.appattest.validator;

import com.webauthn4j.appattest.data.DCAssertionData;
import com.webauthn4j.appattest.data.DCAssertionParameters;
import com.webauthn4j.validator.CoreAuthenticationDataValidator;
import com.webauthn4j.validator.CustomCoreAuthenticationValidator;

import java.util.List;

public class DCAssertionDataValidator extends CoreAuthenticationDataValidator {

    public DCAssertionDataValidator(List<CustomCoreAuthenticationValidator> customAuthenticationValidators) {
        super(customAuthenticationValidators);
    }

    public DCAssertionDataValidator() {
        super();
    }

    public void validate(DCAssertionData dcAssertionData, DCAssertionParameters dcAssertionParameters) {
        validate(dcAssertionData, dcAssertionParameters);
    }
}
