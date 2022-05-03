package Authentication;

import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public interface NonceGenerating {
    static IvParameterSpec getIVAndNonce(){
        byte[] nonceAndCounter = new byte[16];
        byte[] nonceBytes = new byte[4];
        new SecureRandom().nextBytes(nonceBytes);
        // use first 8 bytes as nonce
        Arrays.fill(nonceAndCounter, (byte) 0);
        byte[] iv = IVGenerating.generateIv().getIV();
        System.arraycopy(nonceBytes, 0, nonceAndCounter, 0, 4);
        System.arraycopy(iv, 0, nonceAndCounter, 4, 8);
        IvParameterSpec ivSpec = new IvParameterSpec(nonceAndCounter);
        return ivSpec;
    }
}