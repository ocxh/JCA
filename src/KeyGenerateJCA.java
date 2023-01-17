import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class KeyGenerateJCA {
    public static void main(String[] args) throws NoSuchAlgorithmException{
        //KeyGenerator
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();

        //SecretKeySpec
        SecureRandom random = new SecureRandom();
        byte[] keyData = new byte[16];
        random.nextBytes(keyData);
        SecretKey secretKey = new SecretKeySpec(keyData, "AES");
        //SecretKeySpec origin
        byte[] keyData_origin = secretKey.getEncoded();
    }
}


