package net.sharplab.springframework.security.webauthn.utils;

import net.sharplab.springframework.security.webauthn.util.UnsignedNumberUtil;
import org.junit.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for CUnsignedNumberUtil
 */
public class UnsignedNumberUtilTest {

    @Test
    public void getUnsignedShort_test1(){
        byte[] bytes = new byte[4];
        bytes[0] = 0x00;
        bytes[1] = 0x01;
        long result = UnsignedNumberUtil.getUnsignedShort(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void getUnsignedShort_test2(){
        byte[] bytes = new byte[4];
        bytes[0] = (byte)0xFF;
        bytes[1] = (byte)0xFF;
        long result = UnsignedNumberUtil.getUnsignedShort(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(0xFFFFL);
    }

    @Test
    public void getUnsignedInt_test1(){
        byte[] bytes = new byte[4];
        bytes[0] = 0x00;
        bytes[1] = 0x00;
        bytes[2] = 0x00;
        bytes[3] = 0x01;
        long result = UnsignedNumberUtil.getUnsignedInt(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void getUnsignedInt_test2(){
        byte[] bytes = new byte[4];
        bytes[0] = (byte)0xFF;
        bytes[1] = (byte)0xFF;
        bytes[2] = (byte)0xFF;
        bytes[3] = (byte)0xFF;
        long result = UnsignedNumberUtil.getUnsignedInt(ByteBuffer.wrap(bytes));
        assertThat(result).isEqualTo(0xFFFFFFFFL);
    }

    @Test
    public void toBytes_test1(){
        byte[] bytes = UnsignedNumberUtil.toBytes(0x00000001L);
        assertThat(bytes).hasSize(4);
        assertThat(bytes).isEqualTo(new byte[]{(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01});
    }

    @Test
    public void toBytes_test2(){
        byte[] bytes = UnsignedNumberUtil.toBytes(0xFFFFFFFFL);
        assertThat(bytes).hasSize(4);
        assertThat(bytes).isEqualTo(new byte[]{(byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF});
    }
}
