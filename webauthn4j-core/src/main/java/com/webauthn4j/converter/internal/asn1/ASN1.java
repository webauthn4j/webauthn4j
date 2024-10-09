/*
 * Copyright 2024 the original author or authors.
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


// Portions of the code under `com.webauthn4j.converter.internal.asn1` are derived from work by `io.vertx.ext.auth.impl.asn.ASN1`
// Original site: https://github.com/eclipse-vertx/vertx-auth/blob/4.5.10/vertx-auth-common/src/main/java/io/vertx/ext/auth/impl/asn/ASN1.java
// Original author: Paulo Lopes

/*
 * Original License Header
 */

/*
 * Copyright 2019 Red Hat, Inc.
 *
 *  All rights reserved. This program and the accompanying materials
 *  are made available under the terms of the Eclipse Public License v1.0
 *  and Apache License v2.0 which accompanies this distribution.
 *
 *  The Eclipse Public License is available at
 *  http://www.eclipse.org/legal/epl-v10.html
 *
 *  The Apache License v2.0 is available at
 *  http://www.opensource.org/licenses/apache2.0.php
 *
 *  You may elect to redistribute this code under either of these licenses.
 */

package com.webauthn4j.converter.internal.asn1;

import java.nio.ByteBuffer;
import java.util.List;

public class ASN1 {

    public static ASN1 parse(byte[] bytes) {
        return parse(ByteBuffer.wrap(bytes));
    }

    public static ASN1 parse(ByteBuffer byteBuffer) {
        ASN1Tag tag = ASN1Tag.parse(byteBuffer);
        ASN1Length length = ASN1Length.parse(byteBuffer);
        if(tag.isConstructed()){
            List<ASN1> value = ASN1Structure.parseValue(byteBuffer, tag, length);
            return new ASN1Sequence(tag, length, value); //TODO: non-sequence structure
        }
        else {
            byte[] value = ASN1Primitive.parseValue(byteBuffer, length);
            return new ASN1Primitive(tag, length, value);
        }
    }



    private final ASN1Tag tag;
    private final ASN1Length length;

    ASN1(ASN1Tag tag, ASN1Length length) {
        this.tag = tag;
        this.length = length;
    }

    public ASN1Tag getTag() {
        return tag;
    }

    public ASN1Length getLength() {
        return length;
    }

}
