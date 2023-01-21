import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;

public class Main {
    public static void main(String[] args) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        String plainText = "평문입니다.";

        //비밀 키 생성
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SEED");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        //IV 생성
        SecureRandom random = new SecureRandom();
        byte[] ivData = new byte[16];
        random.nextBytes(ivData);
        IvParameterSpec iv = new IvParameterSpec(ivData);

        //암호화
        byte[] encryptData = encrypt(secretKey, iv,plainText.getBytes());
        print_bytes(encryptData);

        //복호화
        byte[] decryptData = decrypt(secretKey, iv,encryptData);
        System.out.println("Decrypted: "+new String(decryptData));
    }
    public static void print_bytes(byte[] bArr){
        StringBuilder builder = new StringBuilder();

        for (byte data : bArr) {
            builder.append(String.format("%02X ", data));
        }

        System.out.println("Encrypted: "+builder.toString());
    }
    public static byte[] encrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec,byte[] plainText) throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance("SEED");
        cipher.init(1, secretKey, ivParameterSpec);
        byte[] cipherText = cipher.doFinal(plainText);
        return cipherText;
    }
    public static byte[] decrypt(SecretKey secretKey, IvParameterSpec ivParameterSpec,byte[] cipherText) throws GeneralSecurityException{
        Cipher cipher = Cipher.getInstance("SEED");
        cipher.init(2, secretKey, ivParameterSpec);
        byte[] plainText = cipher.doFinal(cipherText);
        return plainText;
    }
}
