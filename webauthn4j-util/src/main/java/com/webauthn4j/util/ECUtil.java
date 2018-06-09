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

package com.webauthn4j.util;

import com.webauthn4j.util.exception.UnexpectedCheckedException;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public class ECUtil {

    private ECUtil(){}

    public static final ECParameterSpec P_256_SPEC = createECParameterSpec("secp256r1");
    public static final ECParameterSpec P_384_SPEC = createECParameterSpec("secp384r1");
    public static final ECParameterSpec P_521_SPEC = createECParameterSpec("secp521r1");

    private static ECParameterSpec createECParameterSpec(String name){
        try {
            AlgorithmParameters parameters = null;
            parameters = AlgorithmParameters.getInstance("EC", "SunEC");
            parameters.init(new ECGenParameterSpec(name));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidParameterSpecException e) {
            throw new UnexpectedCheckedException(e);
        }
    }
}
