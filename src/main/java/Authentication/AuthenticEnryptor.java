package Authentication;

import HMAC.HMAC;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AuthenticEnryptor {
    private HMAC hmac = new HMAC();
    private byte[] iv = null;
    private Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
    private byte[] key1 = null;
    private byte[] key2 = null;
    private byte[] currentEncryptedBlock = null;
    private ByteArrayOutputStream encryptedBlocks = new ByteArrayOutputStream();
    private byte[] tag = null;
    private int blockSize = 16;
    private Mode mode;

    public AuthenticEnryptor(Mode mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.mode = mode;
        initializeIV();
        initializeKeys();
        hmac.setKey(key2);
        hmac.setByteBlockSize(blockSize);
    }

    private void initializeIV() {
        iv = NonceGenerating.getIVAndNonce().getIV();
    }

    private void initializeKeys() throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        SecretKey secretKey1 = KeyGenerating.generateKey();
        SecretKey secretKey2 = KeyGenerating.generateKey();
        key1 = secretKey1.getEncoded();
        key2 = secretKey2.getEncoded();
        cipher.init(mode == Mode.Decryption ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, secretKey1, new IvParameterSpec(iv));
    }

    public void SetKey(byte[] key) {
        key1 = key;
    }

    public void switchMode() throws InvalidKeyException, InvalidAlgorithmParameterException {
        mode = mode == Mode.Ecryption ? Mode.Decryption : Mode.Ecryption;
        encryptedBlocks.reset();
        cipher.init(mode == Mode.Decryption ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, 0, key1.length, "AES"), new IvParameterSpec(iv));
    }

    public byte[] AddBlock(byte[] dataBlock, Boolean isFinal) throws IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException {
        currentEncryptedBlock = cipher.update(dataBlock);

        if (hmac.isEmpty()) {
            encryptedBlocks.write(iv);
            hmac.MacAddBlock(iv);
        }
        encryptedBlocks.write(currentEncryptedBlock);
        hmac.MacAddBlock(currentEncryptedBlock);

        if (isFinal) {
            currentEncryptedBlock = cipher.doFinal();
            tag = hmac.MacFinalize();
            encryptedBlocks.write(tag);
            return encryptedBlocks.toByteArray();
        }
        return currentEncryptedBlock;
    }

    public byte[] ProcessData(byte[] data) throws IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        switch (mode) {
            case Ecryption:
                ProcessEncrypt(data);
                return encryptedBlocks.toByteArray();
            case Decryption:
                ProcessDecrypt(data);
                return Arrays.copyOfRange(encryptedBlocks.toByteArray(), blockSize, encryptedBlocks.size() - 2 * blockSize);
            default:
                return null;
        }
    }

    private void ProcessEncrypt(byte[] data) throws IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException {
        int numOfBlocks = data.length % blockSize == 0 ?
                data.length / blockSize - 1 :
                data.length / blockSize;
        for (int i = 0; i < numOfBlocks; ++i) {
            AddBlock(Arrays.copyOfRange(data, i * blockSize, (i + 1) * blockSize), false);
        }
        AddBlock(Arrays.copyOfRange(data, numOfBlocks * blockSize, data.length), true);
    }

    private void ProcessDecrypt(byte[] data) throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] toDecrypt = Arrays.copyOfRange(data, 0, data.length - blockSize * 2);

        if (!checkAuth(toDecrypt, Arrays.copyOfRange(data, data.length - blockSize * 2, data.length))) {
            System.out.println("ERROR:: Authentication failed.");
            return;
        } else {
            System.out.println("Authentication success.");
        }
        toDecrypt = Arrays.copyOfRange(data, blockSize, data.length - 2 * blockSize);
        iv = Arrays.copyOfRange(data, 0, blockSize);
        cipher.init(mode == Mode.Decryption ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, new SecretKeySpec(key1, 0, key1.length, "AES"), new IvParameterSpec(iv));
        ProcessEncrypt(toDecrypt);
    }

    private boolean checkAuth(byte[] data, byte[] mac) throws NoSuchAlgorithmException, IOException {
        int numOfBlocks = data.length % blockSize == 0 ?
                data.length / blockSize :
                data.length / blockSize + 1;
        HMAC hmac1 = new HMAC(key2);
        hmac1.setByteBlockSize(blockSize);
        for(int i = 0;i<numOfBlocks-1;++i){
            hmac1.MacAddBlock(Arrays.copyOfRange(data, i * blockSize, (i + 1) * blockSize));
        }
        hmac1.MacAddBlock(Arrays.copyOfRange(data, (numOfBlocks-1) * blockSize, data.length));

        byte[] result = hmac1.MacFinalize();
        return Arrays.toString(result).equals(Arrays.toString(mac));
    }
}
