import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

public class Main {
    public static void main(String[] args) throws Exception{
        String plainText = "평문입니다.";

        //비밀 키 생성
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        //암호화
        byte[] encryptData = encrypt(secretKey, plainText.getBytes());
        System.out.println("Encrypted: "+new String(encryptData));

        //복호화
        byte[] decryptData = decrypt(secretKey, encryptData);
        System.out.println("Decrypted: "+new String(decryptData));
    }
    public static byte[] encrypt(SecretKey secretKey, byte[] plainText) throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(1, secretKey);
        byte[] cipherText = cipher.doFinal(plainText);
        return cipherText;
    }
    public static byte[] decrypt(SecretKey secretKey, byte[] cipherText) throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(2, secretKey);
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
    }
}
