package net.sharplab.springframework.security.webauthn.util;

import java.nio.ByteBuffer;

/**
 * A Utility class for unsigned number
 */
public class UnsignedNumberUtil {

    private UnsignedNumberUtil(){}

    public static int getUnsignedShort(ByteBuffer byteBuffer) {
        return (int) byteBuffer.getShort() & 0xffff;
    }

    public static long getUnsignedInt(ByteBuffer byteBuffer) {
        return (long) byteBuffer.getInt() & 0xffffffffL;
    }

    public static byte[] toBytes(int ushortValue) {
        byte[] bytes = new byte[2];
        bytes[1] = (byte) (0x00ff & (ushortValue));
        bytes[0] = (byte) (0x00ff & (ushortValue >>> 8));
        return bytes;
    }

    public static byte[] toBytes(long uintValue) {
        byte[] bytes = new byte[4];
        bytes[3] = (byte) (0x000000ff & (uintValue));
        bytes[2] = (byte) (0x000000ff & (uintValue >>> 8));
        bytes[1] = (byte) (0x000000ff & (uintValue >>> 16));
        bytes[0] = (byte) (0x000000ff & (uintValue >>> 24));
        return bytes;
    }


}
