package hash;


import java.security.MessageDigest;
import java.util.Arrays;

import util.CryptoTools;

public class HMAC {
	public static void main(String[] args) throws Exception{
		String m = "Why do tell actors to break a leg? because every play has a cast";
		String K = "This is a super secure random key!";
		byte[] hmacMessage = CryptoTools.hexToBytes("D936EE8A065CCEF9880A4F55870D66344E9B94BFEC72AF2EAAF06C90EC2E9E4FF2AB3A6586359DBEFDBE90972C2110E4356AA6332493C3FB47A07806951CBACE");
		byte[] messageArray = m.getBytes();
		byte[] keyArray = K.getBytes();
		int blockSize = 64;
		byte[] keyHash = new byte[blockSize];
		
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		if (keyArray.length > blockSize) {
			keyHash = md.digest(keyArray);
		}
		if(keyArray.length < blockSize) {
			for(int x = 0; x < blockSize; x++) {
				if(x >= keyArray.length) {
					keyHash[x] = 0;
				}else {
					keyHash[x] = keyArray[x];
				}
			}
		}
		byte[] outerPad = new byte[keyHash.length];
		for(int x = 0; x < keyHash.length; x++) {
			outerPad[x] = (byte) (keyHash[x] ^ 0x5c);
		}
		byte[] innerPad = new byte[keyHash.length];
		for(int x = 0; x < keyHash.length; x++) {
			innerPad[x] = (byte) (keyHash[x] ^ 0x36);
		}
		byte[] messagePad = new byte[messageArray.length + innerPad.length];
		for(int x =0; x < messagePad.length; x++) {
			if(x < innerPad.length) {
				messagePad[x] = innerPad[x];
			}else {
				messagePad[x] = messageArray[x - innerPad.length];
			}
		}
		byte[] messageHash = md.digest(messagePad);
		byte[] outerHash = new byte[outerPad.length + messageHash.length];
		for(int x =0; x < outerHash.length; x++) {
			if(x < outerPad.length) {
				outerHash[x] = outerPad[x];
			}else {
				outerHash[x] = messageHash[x - outerPad.length];
			}
		}
		byte[] output = md.digest(outerHash);
		if(Arrays.equals(output, hmacMessage)) {
			System.out.println("Same");//message verified
		}
		else {
			System.out.println("not same");
		}
	}
}
