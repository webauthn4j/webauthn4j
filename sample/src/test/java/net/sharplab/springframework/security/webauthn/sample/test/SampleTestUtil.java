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

package net.sharplab.springframework.security.webauthn.sample.test;

import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.util.Base64Utils;

/**
 * A utility class for sample module test
 */
public class SampleTestUtil {

    private SampleTestUtil(){}

    public static User createUser(){
        User user = new User();
        user.setId(1);
        user.setUserHandle(Base64Utils.decodeFromUrlSafeString("TFmvUeeRSQyMUxLDq6x6GA"));
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setEmailAddress("john.doe@example.com");
        user.setPassword("$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq");
        user.setLocked(false);
        return user;
    }
}
