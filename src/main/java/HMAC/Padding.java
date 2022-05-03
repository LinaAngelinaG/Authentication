package HMAC;

import java.util.stream.IntStream;

public interface Padding {
    static byte[] makePadding(byte[] data, int len, int extra) {
        if (data == null) return null;
        int l = (len/16+1)*16;
        if (extra == 0) {
            extra = 16;
        }
        byte[] arr = new byte[l];
        byte paddingOctet = (byte) (extra & 0xff);
        IntStream.range(0, l).forEach(i -> {
            if (i < len) arr[i] = data[i];
            else
                arr[i] = paddingOctet;
        });
        return arr;

    }

    static byte[] makeUnpadding(byte[] data) throws Exception {
        int unpadding = data[data.length - 1] & 0xff;
        if (unpadding > 16) {
            return data;
            //throw new Exception("Decryption Failed");
        }
        byte[] result = new byte[data.length - unpadding];
        for (int i = 0; i < result.length; i++) {
            result[i] = data[i];
        }
        return result;
    }

    static byte[] removeZeros(byte[] data, int del) throws Exception {
        if(del > 0) {
            byte[] result = new byte[data.length - del];
            for (int i = 0; i < result.length; i++) {
                result[i] = data[i];
            }
            return result;
        }
        return data;
    }
}