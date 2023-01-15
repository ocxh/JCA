import java.security.SecureRandom;

public class SecureRandomJCA {
    public static void main(String[] args) throws Exception{
        StringBuilder builder = new StringBuilder();

        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[16];
        random.nextBytes(bytes);

        for (byte data : bytes) {
            builder.append(String.format("%02X ", data));
        }

        System.out.println(builder.toString());
    }
}
