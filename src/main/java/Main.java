import Authentication.AuthenticEnryptor;
import Authentication.KeyGenerating;
import Authentication.Mode;
import Authentication.NonceGenerating;
import HMAC.HMAC;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public class Main {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        AuthenticEnryptor auth = new AuthenticEnryptor(Mode.Ecryption);
        byte[] data = "ckwnsfvdvffffdfdddddvfvfvddvfvfvffvdvfvfvfvfdvfdvfgbtybtyntynynynynnhnhjkcndksvsd".getBytes();
        /*Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKey k = KeyGenerating.generateKey();
        IvParameterSpec iv = NonceGenerating.getIVAndNonce();
        System.out.println(Arrays.toString(iv.getIV()));
        cipher.init(Cipher.ENCRYPT_MODE, k,iv);

        for(int i=0; i< data.length/16-1;++i){
            byte[] t = cipher.update(Arrays.copyOfRange(data,16*i,(i+1)*16));
            System.out.println(Arrays.toString(t));
        }

        System.out.println(Arrays.toString(cipher.doFinal(Arrays.copyOfRange(data,16*(data.length/16-1),(data.length/16)*16+1))));

        byte[] data1 = cipher.doFinal(data);
        Cipher cipher1 = Cipher.getInstance("AES/CTR/NoPadding");

        cipher1.init(Cipher.ENCRYPT_MODE, k,iv);

        byte[] data2 = cipher1.doFinal(data);
        System.out.println(Arrays.toString(data1));
        System.out.println(Arrays.toString(data2));
        System.out.println(Arrays.toString(data1).equals(Arrays.toString(data2)));
        */
        data = createByteArray(100000000);
        //System.out.println(Arrays.toString(data));
        data = auth.ProcessData(data);
        auth.switchMode();

       // System.out.println(Arrays.toString(auth.ProcessData(data)));
    }

    private static byte[] createByteArray(int size){
        byte[] b = new byte[size];
        new Random().nextBytes(b);
        return b;
    }
}
