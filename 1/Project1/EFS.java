

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

/**
 * @author <Zhen Wang>
 * @netid <zxw180035>
 * @email <Zhen.Wang2@utdallas.edu>
 */
public class EFS extends Utility{

    public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }

  
   /**
   } * Steps to consider... <p>
    *  - add padded username and password salt to header <p>
    *  - add password hash and file length to secret data <p>
    *  - AES encrypt padded secret data <p>
    *  - add header and encrypted secret data to metadata <p>
    *  - compute HMAC for integrity check of metadata <p>
    *  - add metadata and HMAC to metadata file block <p>
    */
 @Override
    public void create(String file_name, String user_name, String password) throws Exception {
    // from top to bottom, username, salt, hash(password|| salt), 
	// IV(counter), encrypted file length, MAC. Each data is separated by "\n"
      dir = new File(file_name);
      dir.mkdirs();
      File meta = new File(dir, "0");
      
      
      String toWrite = "";
      toWrite += user_name+"\n";   //add username

      byte[] saltByte = secureRandomNumber(8); // return a byte[8] size random password salt
      // String salt = new String(saltByte, StandardCharsets.UTF_8);  
      String salt = byteArray2String(saltByte);
      toWrite += salt+"\n";       // add salt 
      
      byte[] saltedPasswordByte = concat(password.getBytes(), saltByte);      
      byte[] saltedPasswordHashByte = hash_SHA256(saltedPasswordByte); 
      String saltedPasswordHash = byteArray2String(saltedPasswordHashByte);
      toWrite += saltedPasswordHash+"\n";       // add hash 
      
      byte[] IVByte = secureRandomNumber(12); // return a byte[12],concat it with a 4 byte int, to get a 16 byte, 128 bit size random (IV,ctr) for AES CTR mode
      String IV = byteArray2String(IVByte);
      toWrite += IV+"\n";       // add IV 
              
//      final byte[] length = new byte[16]; 
      String len = "0";
      byte [] lenByte = len.getBytes();
      byte [] lenBytePad16 = padwithAT(lenByte, 16);
//      byte [] lenBytePad16 = new byte[16];
//      for (int i = 0; i < 16; i++) {
//		if(i<lenByte.length)
//			lenBytePad16[i] = lenByte[i];  // every element value is between ascii(0) - ascii(9), 48 - 57
//		lenBytePad16[i] = 64;  				// ascii of @, padded with @
//	 }
      
      
     byte[] encyptedLengthByte = encript_AES(lenBytePad16, derive_AESkey128(user_name, password));
     String encyptedLength = byteArray2String(encyptedLengthByte);
     toWrite +=  encyptedLength+"\n"; ;  //add encyptedLength of the file, a temporary "0" is AES encrypted and added
      
     // MAC should be in the last
     byte[] MACByte =  hash_SHA256(concat(password.getBytes(),toWrite.getBytes()));
     String MAC = byteArray2String(MACByte);
     toWrite += MAC+"\n";       // add MAC
      
      
      //padding
      while (toWrite.length() < Config.BLOCK_SIZE) {
          toWrite += '\0';  
      }

      save_to_file(toWrite.getBytes(), meta);
      return;
      
//      byte[] newLineByte = {10}; //ascii of "\n"
//      
//      byte[] user_nameByte = user_name.getBytes();
//      
//      byte[] user_nameBytePlsNewline = concat(user_nameByte,newLineByte);
//     
//      
//      byte[] saltByte = secureRandomNumber(8); // return a byte[8] size random password salt
////      String salt = byteArray2String(saltByte);
//      byte[] saltBytePlsNewline = concat(saltByte,newLineByte);
//
//      
//      byte[] saltedPasswordByte = concat(password.getBytes(),saltByte);
//      byte[] saltedPasswordHashByte = hash_SHA256(saltedPasswordByte); 
////      String saltedPasswordHash = byteArray2String(saltedPasswordHashByte);
//      byte[] saltedPasswordHashBytePlsNewline = concat(saltedPasswordHashByte,newLineByte);
// 
//      
//      byte[] IVByte = secureRandomNumber(16); // return a byte[16], 128 bit size random IV for AES CTR mode
////      String IV = byteArray2String(IVByte);
//      byte[] IVBytePlsNewline = concat(IVByte,newLineByte);
//      
//   
//      byte[] LenTemp0Byte = {48};   //length of the file, a temporary 0, ascii 
//      
////      byte[] NULLByte = {0};   //NULL, ascii 0 
//
//      byte[] toWrite = concat(concat(concat
//    		  (user_nameBytePlsNewline,saltBytePlsNewline),
//    		  saltedPasswordHashBytePlsNewline),
//    		  IVBytePlsNewline);
//      
////      //padding
////      while (toWrite.length < Config.BLOCK_SIZE) {
////          toWrite += '\0';  
////      }
//
//      save_to_file(toWrite, meta);
//      return;
        
    
    }


   /**
    * Steps to consider... <p>
    *  - check if metadata file size is valid <p>
    *  - get username from metadata <p>
    */
   @Override
   public String findUser(String file_name) throws Exception {
	   return read_wanted_metadata(file_name,"username");
	   
   }

   /**
    * Steps to consider...:<p>
    *  - get password, salt then AES key <p>     
    *  - decrypt password hash out of encrypted secret data <p>
    *  - check the equality of the two password hash values <p>
    *  - decrypt file length out of encrypted secret data
    */
   @Override
   public int length(String file_name, String password) throws Exception {
//		File dir = new File(file_name);
//        File meta = new File(dir, "0");
        int fileLength = 0;

        // if password correct, decrypt encyptedLength
        if(checkPassword(file_name,password)) {
            System.out.println("Correct password from length function"); 
        	byte[] derivedByteAESKey128 = derive_AESkey128(read_wanted_metadata(file_name,"user_name"),password);
        	String encyptedLength = read_wanted_metadata(file_name, "encyptedLength");
        	byte[] paddedLengthByte = decript_AES(encyptedLength.getBytes(),derivedByteAESKey128);
        	String paddedLength =  byteArray2String(paddedLengthByte);
        	StringBuffer paddedLengthBuffer = new StringBuffer(paddedLength);
        	StringBuffer unpaddedLengthBuffer = new StringBuffer(paddedLength);

        	int i = paddedLengthBuffer.length();
        	while(paddedLength.charAt(i-1)=='@') {
        		unpaddedLengthBuffer = new StringBuffer(paddedLengthBuffer.substring(i-(i-1)));
        		i--;
        	}
            fileLength = Integer.parseInt(unpaddedLengthBuffer.toString());  
        }
        
        return fileLength;
   }

   /**
    * Steps to consider...:<p>
    *  - verify password <p>
    *  - check check if requested starting position and length are valid <p>
    *  - decrypt content data of requested length 
    */
   @Override
   public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
   	return null;
   }

   
   /**
    * Steps to consider...:<p>
	 *	- verify password <p>
    *  - check check if requested starting position and length are valid <p>
    *  - ### main procedure for update the encrypted content ### <p>
    *  - compute new HMAC and update metadata 
    */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
    	
    	if(checkPassword(file_name,password)) {
            String str_content = byteArray2String(content);
            File root = new File(file_name);
            int file_length = length(file_name, password);

            if (starting_position > file_length) {
                throw new Exception();
            }


            int len = str_content.length();
            int start_block = starting_position / Config.BLOCK_SIZE;
            int end_block = (starting_position + len) / Config.BLOCK_SIZE;
            // write contents to files starts from #1, coz #0 is for metadata
            for (int i = start_block + 1; i <= end_block + 1; i++) {
                int sp = (i - 1) * Config.BLOCK_SIZE - starting_position;
                int ep = (i) * Config.BLOCK_SIZE - starting_position;
                String prefix = "";
                String postfix = "";
                // when write to the first file ( i mean first file needs to write, not #1) and starting_position not the beginning
                if (i == start_block + 1 && starting_position != start_block * Config.BLOCK_SIZE) {

                    prefix = byteArray2String(read_from_file(new File(root, Integer.toString(i))));
                    // keep the contents before the starting_position
                    prefix = prefix.substring(0, starting_position - start_block * Config.BLOCK_SIZE);
                    sp = Math.max(sp, 0);
                }

                if (i == end_block + 1) {
                    File end = new File(root, Integer.toString(i));
                    if (end.exists()) {

                        postfix = byteArray2String(read_from_file(new File(root, Integer.toString(i))));

                        if (postfix.length() > starting_position + len - end_block * Config.BLOCK_SIZE) {
                        	// keep the contents after the end position
                            postfix = postfix.substring(starting_position + len - end_block * Config.BLOCK_SIZE);
                        } else {
                            postfix = "";
                        }
                    }
                    ep = Math.min(ep, len);
                }

                String toWrite = prefix + str_content.substring(sp, ep) + postfix;

                while (toWrite.length() < Config.BLOCK_SIZE) {
                    toWrite += '\0';
                }

                save_to_file(toWrite.getBytes(), new File(root, Integer.toString(i)));
            }


            //update meta data

            if (content.length + starting_position > length(file_name, password)) {
                String s = byteArray2String(read_from_file(new File(root, "0")));
                String[] strs = s.split("\n");
                strs[0] = Integer.toString(content.length + starting_position);
                String toWrite = "";
                for (String t : strs) {
                    toWrite += t + "\n";
                }
                while (toWrite.length() < Config.BLOCK_SIZE) {
                    toWrite += '\0';
                }
                save_to_file(toWrite.getBytes(), new File(root, "0"));

            }

    		
    	}
    	


    }

   /**
    * Steps to consider...:<p>
 	 *  - verify password <p>
    *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
    */
   @Override
   public boolean check_integrity(String file_name, String password) throws Exception {
   	return true;
 }

   /**
    * Steps to consider... <p>
    *  - verify password <p>
    *  - truncate the content after the specified length <p>
    *  - re-pad, update metadata and HMAC <p>
    */
   @Override
   public void cut(String file_name, int length, String password) throws Exception {
   }
   
   
   // self-defined methods   
   private byte[] concat(byte []b1, byte[] b2) {
	   byte [] combined = new byte[b1.length+b2.length];
	   for (int i = 0; i < b1.length; i++) 
		   combined[i] = b1[i];
	   for (int i =  b1.length; i < b1.length+b2.length; i++) 
		   combined[i] = b2[i-b1.length];
	   return combined;
   }
   
   /**
	 *  - Get salt
	 *  - Calculate hash
	 *  - Compare hash
	 */
   	private boolean checkPassword(String file_name, String password) throws Exception {

        String salt = read_wanted_metadata(file_name,"salt");
		byte[] hash_calculated = hash_SHA256(concat(password.getBytes(), salt.getBytes()));
		String hash = read_wanted_metadata(file_name,"hash");
		if (!byteEquals(hash.getBytes(), hash_calculated))
			throw new PasswordIncorrectException();
		else {
			return true;
		}
	}	
   	
   	private String read_wanted_metadata(String file_name, String metaType) throws Exception {
	    File file = new File(file_name);
	    File meta = new File(file, "0");
	    String s = byteArray2String(read_from_file(meta));
	    String[] strs = s.split("\n");
	    int meteIndex = 0;
	 // from top to bottom, username, salt, hash(password|| salt), 
		// IV(counter), encrypted file length, MAC. Each data is separated by "\n"
	    
	    switch(metaType){
	    case "username" :
	    	meteIndex = 0;
	    case "salt" :
	    	meteIndex = 1;
	    case "hash" :
	    	meteIndex = 2;
	    case "IV" :
	    	meteIndex = 3;
	    case "encyptedLength" :
	    	meteIndex = 4;
	    case "MAC" :
	    	meteIndex = 5;
	    default : 
	    	meteIndex = -1;
	}
	    return strs[meteIndex];
   	}
   	
	private boolean byteEquals(byte[] b1, byte[] b2) {
		if (b1.length != b2.length)
			return false;

		for (int i = 0; i < b1.length; ++i) {
			if (b1[i] != b2[i])
				return false;
		}

		return true;
	} 
	
	 private byte[] int2ByteArray(int value) {
			return new byte[] {
				(byte)(value >>> 24),
				(byte)(value >>> 16),
				(byte)(value >>> 8),
				(byte)value
			};
	 }	
	
	//	we use the first half of sha-256(user_name, password) as the AES key
	private byte[] derive_AESkey128(String user_name, String password) throws Exception{
		byte[] derivedHash256 = hash_SHA256(concat(user_name.getBytes(), password.getBytes()));
		
		// truncate 
		byte[] derivedAESKey = new byte[128];

		for (int i = 0; i < derivedAESKey.length; ++i)
			derivedAESKey[i] = derivedHash256[i];
		return derivedAESKey;
	}
	
	private byte[] AES_CTR(byte[] txt, byte[] key, byte[] nonce, int ctr) {
		if (key.length != 16)
			return null;

		if (txt.length != 16)
			pad(txt, 16);

		byte[] encrypted = new byte[txt.length];
		byte[] plainText;

		for (int i = 0; i < encrypted.length / AES_BLOCK_SIZE; ++i) {
			plainText = concat(nonce, int2ByteArray(ctr));
			try {
				byte[] keyStr = encript_AES(plainText, key);

				int offset = i * AES_BLOCK_SIZE;

				for (int j = 0; j < AES_BLOCK_SIZE; ++j)
					encrypted[j + offset] = (byte)(txt[j + offset] ^ keyStr[j]);
			} catch (Exception e) {
				return null;
			} 

			++ctr; // Each block must have different counter
		}

		return encrypted;
	}
	
	// pad with '@'
	private byte[] padwithAT(byte[] b1, int blockSize) {
		if (b1.length % blockSize == 0)
			return b1;

		int padding = blockSize - (b1.length % blockSize); 
		// pad with 0
		byte[] combined = new byte[b1.length + padding];

		for (int i = 0; i < blockSize; ++i) {
			if(i<b1.length)
				combined[i] = b1[i];
			combined[i] = 64;
		}
       return combined;
	}
	
	private byte[] padwith0(byte[] b1, int blockSize) {
		if (b1.length % blockSize == 0)
			return b1;

		int padding = blockSize - (b1.length % blockSize); 

		byte[] combined = new byte[b1.length + padding];

		for (int i = 0; i < b1.length; ++i)
			combined[i] = b1[i];

		return combined;
	}

}