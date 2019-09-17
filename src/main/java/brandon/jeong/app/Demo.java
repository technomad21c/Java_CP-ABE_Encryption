package brandon.jeong.app;

import java.security.NoSuchAlgorithmException;

import javax.swing.plaf.synth.SynthSeparatorUI;

import co.junwei.bswabe.Bswabe;
import co.junwei.bswabe.BswabeCph;
import co.junwei.bswabe.BswabeCphKey;
import co.junwei.bswabe.BswabeElementBoolean;
import co.junwei.bswabe.BswabeMsk;
import co.junwei.bswabe.BswabePrv;
import co.junwei.bswabe.BswabePub;
import co.junwei.bswabe.SerializeUtils;
import co.junwei.cpabe.AESCoder;

public class Demo {
	final static boolean DEBUG = true;

	static String[] attr_bounty = { "security", "apac", "big", "high" };
	static String[] attr_tester_ok = { "apac", "high","security" };
//	static String[] attr_tester_ko = { "apac","security"};
	static String[] attr_tester_ko = { "high"};
	static String policy = "apac security 2of2 high 2of2";
	
	static byte[] pubByte, mskByte, prvByte, cphByte;
	
	public static void setup() throws NoSuchAlgorithmException {
		BswabePub pub = new BswabePub();
		BswabeMsk msk = new BswabeMsk();
		BswabePrv prv, prv_tester_ok, prv_tester_ko;	
		
		Bswabe.setup(pub, msk);				
		prv = Bswabe.keygen(pub, msk, attr_bounty);		
		prv_tester_ok = Bswabe.delegate(pub, prv, attr_tester_ok);
		prv_tester_ko = Bswabe.delegate(pub, prv, attr_tester_ko);
		
		pubByte = SerializeUtils.serializeBswabePub(pub);
		mskByte = SerializeUtils.serializeBswabeMsk(msk);
		prvByte = SerializeUtils.serializeBswabePrv(prv);
	}
	
	public static byte[] getBytes(String str)
    {
		char[] chars = str.toCharArray();
        byte[] bytes = new byte[chars.length * 2];
        for (int i = 0; i < chars.length; i++)
        {
            bytes[i * 2] = (byte) (chars[i] >> 8);
            bytes[i * 2 + 1] = (byte) chars[i];
        }

        return bytes;
    }

    public static String getString(byte[] bytes)
    {
        char[] chars = new char[bytes.length / 2];
        char[] chars2 = new char[bytes.length / 2];
        for (int i = 0; i < chars2.length; i++)
            chars2[i] = (char) ((bytes[i * 2] << 8) + (bytes[i * 2 + 1] & 0xFF));

        return new String(chars2);
    }
	
	public static String encrypt(byte[] pubByte, String policy, String data) throws Exception {
		BswabePub pub = SerializeUtils.unserializeBswabePub(pubByte);
		
		BswabeCphKey crypted = Bswabe.enc(pub, policy);		
		BswabeCph cph = crypted.cph;
		cphByte = SerializeUtils.bswabeCphSerialize(cph);
		
		byte[] encryptedMessage = AESCoder.encrypt(crypted.key.toBytes(), data.getBytes());
		System.out.println("cipherdata::" + new String(encryptedMessage) + "::");
				
		return getString(encryptedMessage);
	}
	
	public static void decrypt(byte[] pubByte, byte[] mskByte, byte[] prvByte, byte[] cphByte, byte[] cipherData) throws Exception {
		BswabePub pub = SerializeUtils.unserializeBswabePub(pubByte);
		BswabePrv prv = SerializeUtils.unserializeBswabePrv(pub, prvByte);
		BswabeCph cph = SerializeUtils.bswabeCphUnserialize(pub, cphByte);
				
		BswabeElementBoolean result = Bswabe.dec(pub, prv, cph);
		byte[] decryptedMessage = AESCoder.decrypt(result.e.toBytes(), cipherData);
		
		System.out.println("\n*****************************************************************\n");		
		System.out.println("Encrypted  message String: " + cipherData);
		System.out.println("Decrypted  message String: " + new String(decryptedMessage));
		System.out.println("\n*****************************************************************\n");
	}

	public static void main(String[] args) throws Exception {
		setup();
		String data = "simple plain text";
		String cipherData = encrypt(pubByte, policy, data);		
		decrypt(pubByte, mskByte, prvByte, cphByte, getBytes(cipherData));		
//		temp();
	}
	
    public static void temp() throws Exception {		
		BswabePub pub = new BswabePub();
		BswabeMsk msk = new BswabeMsk();
		BswabePrv prv, prv_tester_ok, prv_tester_ko;
		BswabeCph cph;
		BswabeElementBoolean result;

		
		Bswabe.setup(pub, msk);				
		prv = Bswabe.keygen(pub, msk, attr_bounty);		
		prv_tester_ok = Bswabe.delegate(pub, prv, attr_tester_ok);
		prv_tester_ko = Bswabe.delegate(pub, prv, attr_tester_ko);
		
		/* serialize Bswabe object
		 * 
		 */
				
		
		/* 
		 * serialize and unserialize keys
		 */		
		byte[] pubByte = SerializeUtils.serializeBswabePub(pub);
		byte[] mskByte = SerializeUtils.serializeBswabeMsk(msk);
		byte[] prvByte = SerializeUtils.serializeBswabePrv(prv);
		System.out.println("::" + new String(pubByte) + "::");
		System.out.println("::" + new String(mskByte) + "::");
		System.out.println("::" + new String(prvByte) + "::");

		pub = SerializeUtils.unserializeBswabePub(pubByte);
		msk = SerializeUtils.unserializeBswabeMsk(pub, mskByte);
		prv = SerializeUtils.unserializeBswabePrv(pub, prvByte);
		
		Bswabe.setup(pub, msk);
		prv = Bswabe.keygen(pub, msk, attr_bounty);	
		prv_tester_ok = Bswabe.delegate(pub, prv, attr_tester_ok);
		prv_tester_ko = Bswabe.delegate(pub, prv, attr_tester_ko);
		
		BswabeCphKey crypted = Bswabe.enc(pub, policy);
		//crypted = Bswabe.enc(pub, policy);
		cph = crypted.cph;
		byte[] cphByte = SerializeUtils.bswabeCphSerialize(cph);
		
		String message = "plain text";
		byte[] encryptedMessage = AESCoder.encrypt(crypted.key.toBytes(), message.getBytes());	
		System.out.println("ciphermessage ::" + new String(encryptedMessage) + "::");				
		
		
		/* decryption with original prv key */
		cph = SerializeUtils.bswabeCphUnserialize(pub, cphByte);
		result = Bswabe.dec(pub, prv, cph);		
		byte[] decryptedMessage = AESCoder.decrypt(result.e.toBytes(), encryptedMessage);		
				
		System.out.println("\n*****************************************************************\n");
		System.out.println("encryption seed: " + crypted.key.toBytes());
		System.out.println("decryption seed: " + result.e.toBytes());
		if ((result.b == true) && (result.e.equals(crypted.key) == true))
			System.out.println("succeed in decrypt keys");			
		else
			System.err.println("failed to decrypting keys");
		
		System.out.println("\n*****************************************************************\n");
		System.out.println("Encrypted  message: " + encryptedMessage);		
		System.out.println("Decrypted  message: " + decryptedMessage);
		System.out.println("\n*****************************************************************\n");
		System.out.println("Original   message String: " + message);
		System.out.println("Encrypted  message String: " + new String(encryptedMessage));
		System.out.println("Decrypted  message String: " + new String(decryptedMessage));
		System.out.println("\n*****************************************************************\n");

		/* descryption by tester_ok*/
		result = Bswabe.dec(pub, prv_tester_ok, cph);
		decryptedMessage = AESCoder.decrypt(result.e.toBytes(), encryptedMessage);
		System.out.println("\n*****************************************************************\n");
		System.out.println("Original   message String: " + message);
		System.out.println("Encrypted  message String: " + new String(encryptedMessage));
		System.out.println("Decrypted  message String: " + new String(decryptedMessage));
		System.out.println("\n*****************************************************************\n");
		
		
		/* descryption by tester_ko, which generates an error because of predefined policy*/
		result = Bswabe.dec(pub, prv_tester_ko, cph);
		decryptedMessage = AESCoder.decrypt(result.e.toBytes(), encryptedMessage);
		System.out.println("\n*****************************************************************\n");
		System.out.println("Original   message String: " + message);
		System.out.println("Encrypted  message String: " + new String(encryptedMessage));
		System.out.println("Decrypted  message String: " + new String(decryptedMessage));
		System.out.println("\n*****************************************************************\n");
		
		/* AES encyption & decryption test */		
		String seed = "seed";
		encryptedMessage = AESCoder.encrypt(seed.getBytes(), message.getBytes());
		decryptedMessage = AESCoder.decrypt(seed.getBytes(), encryptedMessage);
		System.out.println("Decrypted message: " + new String(decryptedMessage));
	}

	private static void println(Object o) {
		if (DEBUG)
			System.out.println(o);
	}
}
