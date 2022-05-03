package Authentication;

import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public interface IVGenerating {
    static IvParameterSpec generateIv(){
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}