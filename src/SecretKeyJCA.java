import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecretKeyJCA {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        //1. KeyGenerator Class
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();

        //2. SecretKeySpec Class(Import Key)
        SecureRandom random = new SecureRandom();
        byte[] keyData = new byte[16];
        random.nextBytes(keyData);
        //Import
        SecretKey secretKey = new SecretKeySpec(keyData, "AES");
    }
}
