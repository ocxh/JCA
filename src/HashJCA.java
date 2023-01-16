import java.security.MessageDigest;
import java.nio.charset.Charset;
import java.security.SecureRandom;

public class HashJCA {
    public static void main(String[] args) throws Exception{
        StringBuilder builder = new StringBuilder();

        //Hash
        Charset charset = Charset.forName("UTF-8");
        String plainText = "평문입니다.";
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plainText.getBytes(charset));
        byte[] hash = md.digest();

        //print
        for (byte data : hash) {
            builder.append(String.format("%02X ", data));
        }
        System.out.println(builder.toString());
    }
}
