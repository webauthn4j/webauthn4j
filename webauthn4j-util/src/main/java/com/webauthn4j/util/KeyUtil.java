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

import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class KeyUtil {

    private KeyUtil(){}

    public static PrivateKey loadECPrivateKey(byte[] bytes){
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("EC");
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPairGenerator createECKeyPairGenerator(){
        try {
            return KeyPairGenerator.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPair createECKeyPair(byte[] seed, ECParameterSpec ecParameterSpec){
        KeyPairGenerator keyPairGenerator = createECKeyPairGenerator();
        SecureRandom random = null;
        try {
            if(seed!=null){
                random = SecureRandom.getInstance("SHA1PRNG"); // to make it deterministic
                random.setSeed(seed);
            }
            else {
                random = SecureRandom.getInstanceStrong();
            }
            keyPairGenerator.initialize(ecParameterSpec, random);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    public static KeyPair createECKeyPair(byte[] seed) {
        return createECKeyPair(seed, ECUtil.P_256_SPEC);
    }

    public static KeyPair createECKeyPair(ECParameterSpec ecParameterSpec){
        return createECKeyPair(null, ecParameterSpec);
    }

    public static KeyPair createECKeyPair(){
        return createECKeyPair((byte[]) null);
    }
}
