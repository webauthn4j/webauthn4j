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


package com.webauthn4j.data.internal.asn1.der;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Base class for ASN.1 elements in DER (Distinguished Encoding Rules) representation.
 * <p>
 * This class and its subclasses handle DER encoding and decoding only.
 * BER (Basic Encoding Rules) features such as indefinite-length encoding are not supported.
 */
public abstract class ASN1 {

    /**
     * Parse a DER-encoded byte array into an ASN.1 element.
     *
     * @param bytes DER-encoded data
     * @return parsed ASN.1 element (ASN1Primitive subclass or ASN1Structure)
     */
    public static ASN1 parse(byte[] bytes) {
        return parse(ByteBuffer.wrap(bytes));
    }

    /**
     * Parse a DER-encoded ByteBuffer into an ASN.1 element.
     *
     * @param byteBuffer DER-encoded data
     * @return parsed ASN.1 element (ASN1Primitive subclass or ASN1Structure)
     */
    public static ASN1 parse(ByteBuffer byteBuffer) {
        ASN1Tag tag = ASN1Tag.parse(byteBuffer);
        ASN1Length length = ASN1Length.parse(byteBuffer);
        if (tag.isConstructed()) {
            List<ASN1> children = parseChildren(byteBuffer, length);
            return createTypedStructure(tag, length, children);
        }
        else {
            byte[] value = parseValueBytes(byteBuffer, length);
            return createTypedPrimitive(tag, length, value);
        }
    }

    private static byte[] parseValueBytes(ByteBuffer byteBuffer, ASN1Length length) {
        byte[] buffer = new byte[length.getValueLength()];
        byteBuffer.get(buffer);
        return buffer;
    }

    private static List<ASN1> parseChildren(ByteBuffer byteBuffer, ASN1Length length) {
        List<ASN1> res = new ArrayList<>();
        int valueLength = length.getValueLength();
        int readLength = 0;
        while (readLength < valueLength) {
            int beforePos = byteBuffer.position();
            ASN1 newObj = ASN1.parse(byteBuffer);
            int afterPos = byteBuffer.position();
            readLength += afterPos - beforePos;
            res.add(newObj);
        }
        return res;
    }

    private static ASN1Primitive createTypedPrimitive(ASN1Tag tag, ASN1Length length, byte[] value) {
        if (tag.getTagClass() == ASN1Tag.ASN1TagClass.UNIVERSAL) {
            switch (tag.getNumber()) {
                case ASN1Tag.INTEGER:
                    return new ASN1Integer(length, value);
                case ASN1Tag.BIT_STRING:
                    return new ASN1BitString(length, value);
                case ASN1Tag.OCTET_STRING:
                    return new ASN1OctetString(length, value);
                case ASN1Tag.OBJECT_IDENTIFIER:
                    return new ASN1ObjectIdentifier(length, value);
                case ASN1Tag.UTF8_STRING:
                    return new ASN1Utf8String(length, value);
                default:
                    return new ASN1Primitive(tag, length, value);
            }
        }
        return new ASN1Primitive(tag, length, value);
    }

    private static ASN1Structure createTypedStructure(ASN1Tag tag, ASN1Length length, List<ASN1> children) {
        if (tag.getTagClass() == ASN1Tag.ASN1TagClass.UNIVERSAL && tag.getNumber() == ASN1Tag.SEQUENCE) {
            return new ASN1Sequence(length, children);
        }
        return new ASN1Structure(tag, length, children);
    }

    private final ASN1Tag tag;
    private final ASN1Length length;

    /**
     * Constructor for parsed data — preserves the original T, L, V as received.
     */
    ASN1(ASN1Tag tag, ASN1Length length) {
        this.tag = tag;
        this.length = length;
    }

    /**
     * Constructor for programmatic construction — L is computed from content.
     */
    ASN1(ASN1Tag tag, int contentLength) {
        this.tag = tag;
        this.length = new ASN1Length(contentLength);
    }

    ASN1Tag getTag() {
        return tag;
    }

    /**
     * Returns the tag number of this ASN.1 element.
     *
     * @return tag number
     */
    public int getTagNumber() {
        return tag.getNumber();
    }

    /**
     * Returns whether this element is constructed (contains child elements).
     *
     * @return true if constructed, false if primitive
     */
    public boolean isConstructed() {
        return tag.isConstructed();
    }

    /**
     * Returns the length field as parsed from the original DER data,
     * or as computed during programmatic construction.
     *
     * @return the length field
     */
    ASN1Length getLength() {
        return length;
    }

    /**
     * Encode this ASN.1 element to DER byte array (Tag + Length + Value).
     *
     * @return DER-encoded byte array
     */
    public byte[] toBytes() {
        byte[] tagBytes = tag.toBytes();
        byte[] lengthBytes = length.toBytes();
        byte[] contentBytes = getValue();
        byte[] result = new byte[tagBytes.length + lengthBytes.length + contentBytes.length];
        System.arraycopy(tagBytes, 0, result, 0, tagBytes.length);
        System.arraycopy(lengthBytes, 0, result, tagBytes.length, lengthBytes.length);
        System.arraycopy(contentBytes, 0, result, tagBytes.length + lengthBytes.length, contentBytes.length);
        return result;
    }

    /**
     * Returns the value bytes (the V part of TLV).
     *
     * @return value bytes
     */
    protected abstract byte[] getValue();

}
