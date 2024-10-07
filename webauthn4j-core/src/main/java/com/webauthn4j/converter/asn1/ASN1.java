package com.webauthn4j.converter.asn1;

// Adapted from io.vertx.ext.auth.impl.asn.ASN1
// Original code: https://github.com/eclipse-vertx/vertx-auth/blob/f0f869b20a116dc17dc2cfd204705a83048982ff/vertx-auth-common/src/main/java/io/vertx/ext/auth/impl/asn/ASN1.java
// Original author: Paulo Lopes (https://github.com/pmlopes)
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
import io.vertx.core.buffer.Buffer;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ASN1 {

    // Tag and data types
    public final static int ANY = 0x00;
    public final static int BOOLEAN = 0x01;
    public final static int INTEGER = 0x02;
    public final static int BIT_STRING = 0x03;
    public final static int OCTET_STRING = 0x04;
    public final static int NULL = 0x05;
    public final static int OBJECT_IDENTIFIER = 0x06;
    public final static int REAL = 0x09;
    public final static int ENUMERATED = 0x0A;
    public final static int UTF8_STRING = 0x0C;

    public final static int SEQUENCE = 0x10;
    public final static int SET = 0x11;

    public final static int NUMERIC_STRING = 0x12;
    public final static int PRINTABLE_STRING = 0x13;
    public final static int VIDEOTEX_STRING = 0x15;
    public final static int IA5_STRING = 0x16;
    public final static int UTC_TIME = 0x17;
    public final static int GRAPHIC_STRING = 0x19;
    public final static int ISO646_STRING = 0x1A;
    public final static int GENERAL_STRING = 0x1B;

    public final static int UNIVERSAL_STRING = 0x1C;
    public final static int BMP_STRING = 0x1E;


    public final static int CONSTRUCTED = 0x20;
    public final static int CONTEXT_SPECIFIC = 0x80;

    public static byte[] length(int x) {
        if (x <= 127) {
            return new byte[]{(byte) x};
        } else if (x < 256) {
            return new byte[]{(byte) 0x81, (byte) x};
        }
        throw new IllegalArgumentException("length >= 256");
    }

    public static byte[] sequence(byte[] data) {
        final byte sequenceTag = (byte) 0x30;

        return Buffer.buffer()
                .appendByte(sequenceTag)
                .appendBytes(length(data.length))
                .appendBytes(data)
                .getBytes();
    }

    public static class ASN {
        public final ASNTag tag;
        public final List<Object> value;
        public final ASNLength length;

        private ASN(ASNTag tag, ASNLength length, List<Object> value) {
            this.tag = tag;
            this.length = length;
            this.value = value;
        }

        public byte[] binary(int index) {
            return (byte[]) value.get(index);
        }

        public int integer(int index) {
            byte[] bytes = binary(index);
            if (bytes.length > 4) {
                throw new IllegalArgumentException("integer too long");
            }
            int result = 0;
            for (byte b : bytes) {
                result = (result << 8) | (b & 0xFF);
            }
            return result;
        }

        public BigInteger bigInteger(int index) {
            return new BigInteger(binary(index));
        }

        public ASN object(int index) {
            return (ASN) value.get(index);
        }

        public ASN object(int index, int type) {
            ASN object = (ASN) value.get(index);
            if (!object.is(type)) {
                throw new ClassCastException("Object at index(" + index + ") is not of type: " + type);
            }
            return object;
        }

        public String oid(int index) {
            byte[] bytes = object(index, ASN1.OBJECT_IDENTIFIER).binary(0);

            StringBuilder oid = new StringBuilder();

            for (int i = 0; i < bytes.length; i++) {
                int uint8 = Byte.toUnsignedInt(bytes[i]);

                if (i == 0) {
                    int b = uint8 % 40;
                    int a = (uint8 - b) / 40;
                    oid
                            .append(a)
                            .append('.')
                            .append(b);
                } else {
                    if (uint8 < 128) {
                        oid
                                .append('.')
                                .append(uint8);
                    } else {
                        oid
                                .append('.')
                                .append(((uint8 - 128) * 128) + Byte.toUnsignedInt(bytes[i + 1]));
                        i++;
                    }
                }
            }

            return oid.toString();
        }

        public int length() {
            return value.size();
        }

        public boolean is(int number) {
            if (tag.constructed) {
                return tag.type == CONSTRUCTED + number;
            } else {
                return tag.type == number;
            }
        }
    }

    public static class ASNTag {
        public final int type;
        public final boolean constructed;
        public final int number;
        private final int nextPos;

        private ASNTag(int type, boolean constructed, int number, int nextPos) {
            this.type = type;
            this.constructed = constructed;
            this.number = number;
            this.nextPos = nextPos;
        }
    }

    public static class ASNLength {
        public final boolean indefinite;
        public final int contentLength;
        private final int nextPos;

        private ASNLength(boolean indefinite, int contentLength, int nextPos) {
            this.indefinite = indefinite;
            this.contentLength = contentLength;
            this.nextPos = nextPos;
        }
    }

    public static ASN parseASN1(byte[] buffer) {
        return parseASN1(Buffer.buffer(buffer), 0);
    }

    public static ASN parseASN1(Buffer buffer) {
        return parseASN1(buffer, 0);
    }

    public static ASN parseASN1(Buffer buffer, int startPos) {
        ASNTag tag = readTag(buffer, startPos);
        ASNLength length = readLength(buffer, tag.nextPos);
        List<Object> value = readValue(buffer, length.nextPos, tag, length);
        return new ASN(tag, length, value);
    }

    private static final int CLASS_MASK = 0b11000000;
    private static final int CONSTRUCTED_MASK = 0b00100000;
    private static final int NUMBER_MASK = 0b00011111;
    private static final int LEADING_BIT_MASK = 0b10000000;

    private static ASNTag readTag(Buffer buffer, int startPos) {
        int pos = startPos;
        int firstByte = buffer.getUnsignedByte(pos++);
        boolean tagConstructed = (firstByte & CONSTRUCTED_MASK) > 0;
        int tagNumber = 0;
        if ((firstByte & NUMBER_MASK) != NUMBER_MASK) {
            // non-extended (8.1.2.3)
            tagNumber = firstByte & NUMBER_MASK;
        } else {
            // extended (8.1.2.4)
            while (true) {
                int octet = buffer.getUnsignedByte(pos++);
                tagNumber = tagNumber * 128 + (octet & ~LEADING_BIT_MASK);
                if ((octet & LEADING_BIT_MASK) == 0) break;
            }
        }

        return new ASNTag(firstByte, tagConstructed, tagNumber, pos);
    }

    private static ASNLength readLength(Buffer buffer, int startPos) {
        int pos = startPos;
        int firstByte = buffer.getUnsignedByte(pos++);
        boolean longForm = (firstByte & LEADING_BIT_MASK) != 0;
        int contentLength = 0;
        if (!longForm) {
            // definite short form (8.1.3.4)
            contentLength = firstByte & ~LEADING_BIT_MASK;
        } else {
            // either definite long form (8.1.3.5) or indefinite form (8.1.3.6)
            int lengthOctets = firstByte & ~LEADING_BIT_MASK;
            while (pos <= startPos + lengthOctets) {
                contentLength = contentLength * 256 + buffer.getUnsignedByte(pos++);
            }
        }

        return new ASNLength(longForm && contentLength == 0, contentLength, pos);
    }

    private static List<Object> readValue(Buffer buffer, int startPos, ASNTag tagObj, ASNLength lengthObj) {
        List<Object> res = new ArrayList<>();
        int pos = startPos;
        if (!tagObj.constructed) {
            res.add(buffer.getBytes(pos, startPos + lengthObj.contentLength));
        } else {
            while (pos < startPos + lengthObj.contentLength) {
                ASN newObj = parseASN1(buffer, pos);
                pos = newObj.length.nextPos + newObj.length.contentLength;

                if (
                        newObj.tag.type == 0 &&
                                !newObj.tag.constructed &&
                                newObj.tag.number == 0 &&
                                newObj.length.contentLength == 0) break; // end-of-contents contents (8.1.5)

                res.add(newObj);
            }
        }

        return res;
    }
}