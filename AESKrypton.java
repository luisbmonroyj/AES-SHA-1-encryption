import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
/**
 *
 * @author Shaitan
 */
public class AESKrypton {
    private SecretKeySpec keyGenerator(String key) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        //converts the key into bytes
        byte[] encryptionKey = key.getBytes("UTF-8");
        //creating an object with sha-1 algorithm
        MessageDigest msgDgst = MessageDigest.getInstance("SHA-1");
        //creating the encription key for the aes 
        encryptionKey = msgDgst.digest(encryptionKey);
        //truncating the key to have 16 bytes
        encryptionKey = Arrays.copyOf(encryptionKey, 16);
        //creating and returning the secretKey object for the cipher object with aes
        return new SecretKeySpec(encryptionKey, "AES");
    }
    public String encrypt(String data, String llave) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        //creating the secretkey object for the cipher object
        SecretKeySpec secretKey = this.keyGenerator(llave);
        //creating the cipher with the secretKey
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");        
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //converting the data to be encrypted into bytes
        byte[] encryptedBytes = cipher.doFinal(data.getBytes("UTF-8"));
        String encryptedData = Base64.getEncoder().encodeToString(encryptedBytes);
        return encryptedData;
    }
    public String decrypt(String encryptedData, String llave) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        //creating the secretkey object for the cipher object
        SecretKeySpec secretKey = this.keyGenerator(llave);
        //creating the cipher with the secretKey
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        //decrypting        
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = cipher.doFinal(encryptedBytes);
        //returning the decrypted data  into String
        return new String(decryptedData);
    }
}
