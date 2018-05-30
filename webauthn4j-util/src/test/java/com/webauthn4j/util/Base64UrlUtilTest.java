package com.webauthn4j.util;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Base64UrlUtilTest {

    @Test
    public void encode_test(){
        byte[] data = new byte[]{0x01, 0x23, 0x45};
        byte[] expected = new byte[]{0x41, 0x53, 0x4E, 0x46};
        byte[] result = Base64UrlUtil.encode(data);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void decode_test(){
        byte[] data = new byte[]{0x41, 0x53, 0x4E, 0x46};
        byte[] expected = new byte[]{0x01, 0x23, 0x45};
        byte[] result = Base64UrlUtil.decode(data);
        assertThat(result).isEqualTo(expected);
    }
}
