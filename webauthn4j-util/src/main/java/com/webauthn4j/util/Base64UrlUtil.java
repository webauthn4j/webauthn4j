package com.webauthn4j.util;

import java.util.Base64;

public class Base64UrlUtil {

    private static java.util.Base64.Decoder decoder = Base64.getUrlDecoder();
    private static java.util.Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    private Base64UrlUtil(){}

    public static byte[] decode(String source){
        return decoder.decode(source);
    }

    public static byte[] encode(byte[] source){
        return encoder.encode(source);
    }

    public static String encodeToString(byte[] source){
        return encoder.encodeToString(source);
    }
}
