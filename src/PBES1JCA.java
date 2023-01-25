import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

//based on PBKDF1
public class PBES1 {
    public static void main(String[] args) throws Exception{
        char[] password = "".toCharArray();
        byte[] salt = new byte[8];
        int iterCount = 1000;
        String plainText;
        byte[] cipherText;

        //Encryption
        plainText = "평문입니다.";
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        cipherText = encrypt(password, salt, iterCount, plainText.getBytes());
        print_bytes(cipherText);

        //Decryption
        plainText = new String(decrypt(password, salt, iterCount, cipherText));
        System.out.println("Decrypted: "+plainText);
    }
    public static byte[] encrypt(char[] password, byte[] salt, int iterCount, byte[] plainText) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PBEKeySpec keySpec = new PBEKeySpec(password);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        PBEParameterSpec params = new PBEParameterSpec(salt, iterCount);

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(1, secretKey, params);
        byte[] encrypted = cipher.doFinal(plainText);

        return encrypted;
    }
    public static byte[] decrypt(char[] password, byte[] salt, int iterCount, byte[] cipherText) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PBEKeySpec keySpec = new PBEKeySpec(password);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        PBEParameterSpec params = new PBEParameterSpec(salt, iterCount);

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
        cipher.init(2, secretKey, params);
        byte[] decrypted = cipher.doFinal(cipherText);

        return decrypted;
    }
    public static void print_bytes(byte[] bArr){
        StringBuilder builder = new StringBuilder();

        for (byte data : bArr) {
            builder.append(String.format("%02X ", data));
        }

        System.out.println("Encrypted: "+builder.toString());
    }
}
