package HMAC;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class AES {
    private byte[] key = null;
    private static final int BL = 16;
    private byte[] iv = null;

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public byte[] AesBlockEncrypt(byte[] key, byte[] data) {
        if (data == null) return null;
        this.key = key;
        generationIVifNULL();
        byte[] result = new byte[(data.length/BL + 2) * BL];
        writeIVToResult(result, iv);
        makeAllEncryptionOperations(result,data);
        return result;
    }

    private void generationIVifNULL(){
        iv = iv == null ? generateIv().getIV() : iv;
    }

    static IvParameterSpec generateIv(){
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            return new IvParameterSpec(iv);
    }


    private void writeIVToResult(byte[] result, byte[] iv) {
        for (int i = 0; i < iv.length; ++i) {
            result[i] = iv[i];
        }
    }

    private void makeAllEncryptionOperations(byte[] result, byte[] data) {
        int l = data.length / BL;
        for (int i = 0; i < l; ++i) {
            byte[] res = ECBEncrypt(Arrays.copyOfRange(data, i * BL, (i + 1) * BL));
            for (int j = 0; j < BL; ++j) {
                result[(1 + i) * BL + j] = res[j];
            }
        }
        if (data.length % BL != 0) {
            byte[] res = ECBEncrypt(Arrays.copyOfRange(data, l * BL, data.length));
            for (int j = 0; j < res.length; ++j) {
                result[(1 + l) * BL + j] = res[j];
            }
        }
        else{
            byte[] res = Padding.makePadding(iv, 0, 0);
            res = ECBEncrypt(res);
            for (int j = 0; j < res.length; ++j) {
                result[(1 + l) * BL + j] = res[j];
            }
        }
    }

    private byte[] ECBEncrypt(byte[] data) {
        if (data.length % BL != 0) {
            data = Padding.makePadding(data, data.length, BL - data.length);
        }
        data = BlockCipherEncrypt(data);
        return data;
    }

    public byte[] BlockCipherEncrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPADDING");
            if (key != null) {
                SecretKey keyBytes = new SecretKeySpec(key, 0, key.length, "AES");
                cipher.init(Cipher.ENCRYPT_MODE, keyBytes);
            } else {
                SecretKey secretKey = KeyGenerating.generateKey();
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }
            return cipher.doFinal(data);
        } catch (NoSuchPaddingException | java.security.InvalidKeyException | javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException | NoSuchAlgorithmException e) {
            return null;
        }
    }
}