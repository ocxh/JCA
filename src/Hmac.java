
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.Mac;
import java.nio.charset.Charset;


public class HmacJCA {
    public static void main(String[] args) throws Exception{
        StringBuilder builder = new StringBuilder();
        Charset charset = Charset.forName("UTF-8");
        String plainText = "평문입니다.";

        //Generate Key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
        SecretKey key = keyGenerator.generateKey();

        //HMAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        byte[] macData = mac.doFinal(plainText.getBytes(charset));

        //print
        for (byte data : macData) {
            builder.append(String.format("%02X ", data));
        }
        System.out.println(builder.toString());
    }

}
