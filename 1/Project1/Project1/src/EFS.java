/**
 * @author <Zhen Wang>
 * @netid <zxw180035>
 * @email <Zhen.Wang2@utdallas.edu>
 */

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;


public class EFS extends Utility{

	final int MAX_USER_LEN = 128;
	final int SALT_LEN = 8;
	final int HASH256_32_OUTPUTBYTE = 32;
	final int IV_LEN = 12;
	final int MAC_LEN = 32;  // also result of hash, so 32 bytes
	final int FILE_LEN_INPUT_OUTOUT_FORAES = 16; // both input and output of AES ECB 128bits, 16 bytes
	final int AESKEY_LEN = 16; // AES ECB key 128bits, 16 bytes
	
    public EFS(Editor e)
    {
        super(e);
        set_username_password();
    }

   
    /**
     * Steps to consider... <p>
     *  - add padded username and password salt to header <p>
     *  - add password hash and file length to secret data <p>
     *  - AES encrypt padded secret data <p>
     *  - add header and encrypted secret data to metadata <p>
     *  - compute HMAC for integrity check of metadata <p>
     *  - add metadata and HMAC to metadata file block <p>
     */
    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
    	
     		
    	  dir = new File(file_name);
          dir.mkdirs();
          File meta = new File(dir, "0");
  		
          byte[] paddedUsername = pad(user_name.getBytes(), MAX_USER_LEN);    // in metadata, MAX_USER_LEN bytes
          
          
   		System.out.println(byteArray2String(paddedUsername));

          byte[] salt = secureRandomNumber(SALT_LEN);                         // in metadata, SALT_LEN bytes
          
          byte[] saltedPassword = concat(password.getBytes(), salt);            
          byte[] saltedPasswordHash = hash_SHA256(saltedPassword); 		      // in metadata, HASH256_32_OUTPUTBYTE 
          
          byte[] IV = secureRandomNumber(IV_LEN);                             // in metadata, IV_LEN bytes
          
//          byte[] FileLen = {48};
          int FileLen = 0;
          byte[] FileLenByteArray = int2Byte_ascii_array(FileLen);
          byte[] paddedFileLen = pad(FileLenByteArray,FILE_LEN_INPUT_OUTOUT_FORAES);
          byte[] derivedAESkey = derive_AESkey128(hash_SHA256(password.getBytes()));
          byte[] encryptedFileLen = encript_AES(paddedFileLen,derivedAESkey); // in metadata, FILE_LEN_INPUT_OUTOUT_FORAES bytes
            
          // * metadata size: MAX_USER_LEN + SALT_LEN + HASH256_32_OUTPUTBYTE + IV_LEN + FILE_LEN_INPUT_OUTOUT_FORAES
          
          byte[] metadata = concat(concat(concat(concat(paddedUsername,salt),saltedPasswordHash),IV),encryptedFileLen); 
          
          byte[] MAC = hash_SHA256(concat(password.getBytes(),metadata));    // in first file, HASH256_32_OUTPUTBYTE bytes
          

          my_save_to_file(concat(metadata,MAC),meta,0);
          
              
    }

    /**s
     * Steps to consider... <p>
     *  - check if metadata file size is valid <p>
     *  - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
		File dir = new File(file_name);
		File meta = new File(dir, "0");

//		if (meta.length() != META_SIZE)
//			return "";
		return byteArray2String(my_read_from_file(meta,0,MAX_USER_LEN));
//      return new String(read_from_file(meta, 0, MAX_USER_LEN)).trim();
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
    	File dir = new File(file_name);
        File meta = new File(dir, "0");
        int fileLength = 0;
 
        if(checkPassword(meta,password)) {
        	 // decrypt and get fileLength 
            byte[] derivedAESkey = derive_AESkey128(hash_SHA256(password.getBytes()));
//            	System.out.println("before read in length fn");
            byte[] encryptedFileLen =  my_read_from_file(meta,MAX_USER_LEN + SALT_LEN + HASH256_32_OUTPUTBYTE + IV_LEN, FILE_LEN_INPUT_OUTOUT_FORAES);
//            	System.out.println("after read in length fn"+" bytes number of encryptedFileLen is"+ encryptedFileLen.length);
            byte[] decryptedFileLen = decript_AES(encryptedFileLen,derivedAESkey);
            
            fileLength = Byte_ascii_array2int(decryptedFileLen);
            System.out.println("end file() fileLength is "+fileLength);

        }
        else{
        	fileLength = 0;
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
    	File root = new File(file_name);
        File meta = new File(dir, "0");
        int file_length = length(file_name, password);   
        
        if (starting_position > file_length) {
            throw new Exception();
        }
        
        if(!checkPassword(meta,password))
        	return null;
        if(file_length%16!=0) {
        	file_length = file_length + 16- (file_length%16);
        }
        byte[] encryptedWhole = new byte[file_length];
        byte[] decryptedWhole = new byte[file_length];

        // copy all the contents from first block to end_block, end_block file may not be full, but it is fine coz i read to the end 
        for (int i = 1; i <= (file_length/Config.BLOCK_SIZE) + 1; i++) {
      	    
            System.out.println("inside read: before read_from_file");

        	byte[] temp = read_from_file(new File(root, Integer.toString(i)));
        	
            System.out.println("inside read: after read_from_file");

        	for (int j = 0; j < temp.length; j++) {
        		
                System.out.println(" inside read: inside for tmp length is"+temp.length);
        		encryptedWhole[(i-1)*Config.BLOCK_SIZE+j]= temp[j];
			}
        	
        }	
        System.out.println("inside read: after for");

        // 1024/16=64,the end file size also the multiple of 16 coz we use pad
        byte[] derivedAESkey = derive_AESkey128(hash_SHA256(password.getBytes()));
        for (int i = 1; i <= file_length/16; i++) {
        	
        	byte[] temp2 = decript_AES( Arrays.copyOfRange(encryptedWhole,  (i-1)*16,  i*16),derivedAESkey);
        	for (int j = 0; j < temp2.length; j++) {
        		decryptedWhole[(i-1)*16+j]= temp2[j];
			}
		}

        System.out.println("inside read: before it returns");

        return Arrays.copyOfRange(decryptedWhole, starting_position,  starting_position+len);
    	
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
        
        System.out.println("start write ");

//    	String str_content = byteArray2String(content);
    	File root = new File(file_name);
        File meta = new File(dir, "0");
        int file_length = length(file_name, password);   
        
        if (starting_position > file_length) {
            throw new Exception();
        }
        
        if(!checkPassword(meta,password))
        	return ;
        
        int len = content.length;
        
        System.out.println("content length: "+ len);
        
        byte[] ReaddecryptedWhole = new byte[file_length];
        
        if(file_length != 0)
        	 ReaddecryptedWhole = read(file_name,0,file_length,password);
        
        System.out.println("after read inside write ");
        
        int oldfile_length = file_length;
        
        if ((starting_position + len)>file_length)
        	file_length = starting_position + len;
        
 
        byte[] plaintextAfterWrite = new byte[file_length];
        
        // update plaintext 
        for (int i = 0; i < file_length; i++) {
        	
        	if (oldfile_length == file_length && oldfile_length!=0) {
        		
				if(i<starting_position)
					plaintextAfterWrite[i] = ReaddecryptedWhole[i];
				else if( (i>=starting_position) && (i<(starting_position+len)) )
					plaintextAfterWrite[i] = content[i-starting_position];
				else 
					plaintextAfterWrite[i] = ReaddecryptedWhole[i];
			
        	}
        	else {
        		
        		if(i<starting_position && oldfile_length!=0 )
					plaintextAfterWrite[i] = ReaddecryptedWhole[i];
        		else 
        			plaintextAfterWrite[i] = content[i-starting_position];
        	}
		}
        System.out.println("after  update plaintext ");
        
        oldfile_length = file_length; 
        // make sure the file_length is the multiple of 16
        int file_length_pad = file_length%16==0? file_length : file_length + ( 16 - (file_length%16));
        
        byte[] plaintextAfterWritePad = new byte[file_length_pad];
        for (int i = 0; i < plaintextAfterWritePad.length; i++) {
        	
        	plaintextAfterWritePad[i] = 0; // pad with zero
        	if(i < oldfile_length)
        		plaintextAfterWritePad[i] = plaintextAfterWrite[i];
		}
        
        
        byte[] ciphertoStore = new byte[file_length_pad]; 
        byte[] derivedAESkey = derive_AESkey128(hash_SHA256(password.getBytes()));
        //  encript_AES() 
        for (int i = 1; i <= file_length_pad/16; i++) {
        	
        	byte[] temp = encript_AES( Arrays.copyOfRange(plaintextAfterWritePad, (i-1)*16,  i*16), derivedAESkey);
        	for (int j = 0; j < temp.length; j++) {
        		ciphertoStore[(i-1)*16+j]= temp[j];
			}
		}
       
        for (int i = 1; i <= file_length_pad/Config.BLOCK_SIZE ; i++) {
			
        	save_to_file( Arrays.copyOfRange(ciphertoStore, (i-1)*Config.BLOCK_SIZE,  i*Config.BLOCK_SIZE), new File(root, Integer.toString(i)));
		}
        // the last save
        save_to_file( Arrays.copyOfRange(ciphertoStore, file_length_pad/Config.BLOCK_SIZE*Config.BLOCK_SIZE,  file_length_pad), new File(root, Integer.toString(file_length_pad/Config.BLOCK_SIZE + 1)));
        
        
        // update metadata  (encryptedFileLen, MAC)
        byte[] FileLenByteArray = int2Byte_ascii_array(file_length);
        byte[] paddedFileLen = pad(FileLenByteArray,FILE_LEN_INPUT_OUTOUT_FORAES);
        byte[] encryptedFileLen = encript_AES(paddedFileLen,derivedAESkey); // in metadata, FILE_LEN_INPUT_OUTOUT_FORAES bytes
        my_save_to_file(encryptedFileLen,meta,MAX_USER_LEN + SALT_LEN + HASH256_32_OUTPUTBYTE + IV_LEN);   
        // * metadata size: MAX_USER_LEN + SALT_LEN + HASH256_32_OUTPUTBYTE + IV_LEN + FILE_LEN_INPUT_OUTOUT_FORAES
        byte[] newmetadata =  my_read_from_file(meta,0, MAX_USER_LEN + SALT_LEN + HASH256_32_OUTPUTBYTE + IV_LEN + FILE_LEN_INPUT_OUTOUT_FORAES);    
        byte[] newMAC = hash_SHA256(concat(password.getBytes(),newmetadata)); 
        my_save_to_file(newMAC,meta,MAX_USER_LEN + SALT_LEN + HASH256_32_OUTPUTBYTE + IV_LEN + FILE_LEN_INPUT_OUTOUT_FORAES);
        
    }

    /**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata and physical file blocks<p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
    	File root = new File(file_name);
        File meta = new File(dir, "0");
         
//        if(!checkPassword(meta,password))
//        	return (Boolean) null;
//    	
//        byte[] metadataRead =  my_read_from_file(meta,0, MAX_USER_LEN + SALT_LEN + HASH256_32_OUTPUTBYTE + IV_LEN + FILE_LEN_INPUT_OUTOUT_FORAES);  
//        byte[] MACRead =  my_read_from_file(meta,MAX_USER_LEN + SALT_LEN + HASH256_32_OUTPUTBYTE + IV_LEN + FILE_LEN_INPUT_OUTOUT_FORAES,HASH256_32_OUTPUTBYTE);  
//        byte[] MACCalculated = hash_SHA256(concat(password.getBytes(),metadataRead));
//        
//        if (!byteEquals(MACRead, MACCalculated)) {
//			return false;
//		}
        
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
    	File root = new File(file_name);
        File meta = new File(dir, "0");
         
        if(!checkPassword(meta,password)){}
        
        int file_length = length(file_name, password); 
        
        if (file_length <= 0)
        	return ;
//        
//        if (length <= Config.BLOCK_SIZE)
//        {
//        	byte[] remaningData = read( file_name, 0,  length, password);
//        	
//
//    		for (int fn =  1; fn <= file_length/Config.BLOCK_SIZE+1; ++fn) { // Delete blocks
//    			File del = new File(dir, String.valueOf(fn));
//    			del.delete();
//    		}
//    		
//    		write(file_name, 0, remaningData,  password);
//    		
//        }
        
        
        
    }
    
    // * SELF defined methods *//
    
    // pad with 0, char(0) is empty, NUL
	private byte[] pad(byte[] b1, int blockSize) {
		if (b1.length % blockSize == 0)
			return b1;

		int padding = blockSize - (b1.length % blockSize); 

		byte[] combined = new byte[b1.length + padding];

		for (int i = 0; i < b1.length; ++i)
			combined[i] = b1[i];

		return combined;
	}
	
	private byte[] concat(byte []b1, byte[] b2) {
		   byte [] combined = new byte[b1.length+b2.length];
		   for (int i = 0; i < b1.length; i++) 
			   combined[i] = b1[i];
		   for (int i =  b1.length; i < b1.length+b2.length; i++) 
			   combined[i] = b2[i-b1.length];
		   return combined;
	   }
	
	public void my_save_to_file(byte[] s, File file, int start_point) throws IOException {
		if (file == null) {
		    return;
		}
		
		try {
			RandomAccessFile raf = new RandomAccessFile(file, "rw");
		    raf.seek(start_point);
		
		    for (int i = 0; i < s.length; i++) {
		    	 raf.writeByte(s[i]);
			}
		   
		    raf.close();
		    
		   } catch (IOException ex) {
	         ex.printStackTrace();
       }
			
	}
	
	
	
	public byte[] my_read_from_file(File file, int start_point, int len) throws Exception {
		DataInputStream in = new DataInputStream(
		        new BufferedInputStream(
		        new FileInputStream(file)));
		try {	
			int size = in.available();
			
			byte[] toR = new byte[size];
			byte[] toReturn = new byte[len];
			
			in.read(toR);
			
			in.close();
			int j = 0;
			for (int i = 0; i < len; i++) {
				j = i + start_point;
				toReturn[i] = toR[j];
			}
			return toReturn;	} 
		catch (java.io.IOException e) {
				System.out.println("Message: " + e.getMessage());
				System.out.println("Exeption: " + e.toString());
				return null;
			}
		
	
	}
	
	//	we use the first half of sha-256(user_name, password) as the AES key
	private byte[] derive_AESkey128(byte[] password) throws Exception{
		
		byte[] derivedHash256 = hash_SHA256(password);	
		// truncate 
		byte[] derivedAESKey = new byte[AESKEY_LEN];

		for (int i = 0; i < derivedAESKey.length; ++i)
			derivedAESKey[i] = derivedHash256[i];
		return derivedAESKey;
	}
	
   	private boolean checkPassword(File file, String password) throws Exception {

        byte[] salt = my_read_from_file(file,MAX_USER_LEN,SALT_LEN);
		byte[] hash_calculated = hash_SHA256(concat(password.getBytes(), salt));
		byte[] hash = my_read_from_file(file,MAX_USER_LEN+SALT_LEN,HASH256_32_OUTPUTBYTE);
		if (!byteEquals(hash, hash_calculated)) {
			throw new PasswordIncorrectException();
		}
		else {
            System.out.println("end of checkPassword check: true");
			return true;
		}
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
	
//	public long byteToInt(byte[] bytes, int length) {
//        int val = 0;
//        if(length>4) throw new RuntimeException("Too big to fit in int");
//        for (int i = 0; i < length; i++) {
//            val=val<<8;
//            val=val|(bytes[i] & 0xFF);
//        }
//        return val;
//    }
	
	// convert int 12345 to byte[]={49,50,51,52,53} ascii of 1,2,3,4,5
    private byte[] int2Byte_ascii_array(int num){
    	
    	 String numStr = String.valueOf(num);
    	 byte[] int2Byte_ascii_array = new byte[numStr.length()];
    	 for (int i = 0; i < numStr.length(); i++) {
			// (byte) cast will get the ascii value of a char
    		 int2Byte_ascii_array[i] = (byte) numStr.charAt(i);
    		 
		}
    	 
    	return int2Byte_ascii_array;
    	
    }
    
    // the Byte_ascii_array should contain less than 16 elements, i.e., length less than 16 bits, a very large num already.
    private int Byte_ascii_array2int(byte[] Byte_ascii_array) {
    	int length = 0;
    	int indexof1stZero = 0;
    	// trim the zero element, coz ascii 0 is NUL, we dont need it 
    	for (int i = 0; i < Byte_ascii_array.length; i++) {
			if(Byte_ascii_array[i]==0){
				indexof1stZero = i;
				break;}
		}
    	byte [] trimedByte_ascii_array = new byte[indexof1stZero];
    	for (int i = 0; i < indexof1stZero; i++) {
    		trimedByte_ascii_array[i] = Byte_ascii_array[i];
    		System.out.println(trimedByte_ascii_array[i]);

		}
    	
    	length = Integer.parseInt(byteArray2String(trimedByte_ascii_array));
    	
    	return length;
    }
  
}


//import java.io.BufferedInputStream;
//import java.io.DataInputStream;
//import java.io.DataOutputStream;
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
//import java.io.IOException;
//import java.io.RandomAccessFile;
//
//public class EFS extends Utility {
//
//	final int SHA512_BLOCKSIZE = 64;
//	final byte IPAD_VALUE = 0x36;
//	final byte OPAD_VALUE = 0x5c;
//
//	final int AES_BLOCK_SIZE = 16;
//	final int AES_KEY_SIZE = 16;
//	final int AES_BLOCKS_PER_FILE = Config.BLOCK_SIZE / AES_BLOCK_SIZE;
//
//	final int MAX_PASSWORD_LEN = 128;
//	final int MAX_USER_LEN = 128;
//
//	final int SALT_LEN = 64;
//	final int SALT_OFFSET = MAX_USER_LEN;
//
//	final int HASH_OFFSET = SALT_OFFSET + SALT_LEN;
//	final int HASH_SIZE = SHA512_BLOCKSIZE;
//
//	final byte[] LEN = new byte[16]; // Initialized with 0
//	final int LEN_OFFSET = HASH_OFFSET + HASH_SIZE;
//
//	final int NONCE_SIZE = 4;
//	final int NONCE_OFFSET = LEN_OFFSET + LEN.length;
//
//	final int HMAC_OFFSET = NONCE_OFFSET + NONCE_SIZE;
//	final int HMAC_SIZE = SHA512_BLOCKSIZE;
//
//	final String META_NAME = "0";
//	final int META_SIZE = HMAC_OFFSET + HMAC_SIZE;
//
//    public EFS(Editor e)
//    {
//        super(e);
//        set_username_password();
//    }
//
//   
//    /**
//     * Steps to consider... <p>
//     *  - add padded username and password salt to header <p>
//     *  - add password hash and file length to secret data <p>
//     *  - AES encrypt padded secret data <p>
//     *  - add header and encrypted secret data to metadata <p>
//     *  - compute HMAC for integrity check of metadata <p>
//     *  - add metadata and HMAC to metadata file block <p>
//     */
//    @Override
//    public void create(String file_name, String user_name, String password) throws Exception {
//		
//        dir = new File(file_name);
//        dir.mkdirs();
//        File meta = new File(dir, META_NAME);
//
//		byte[] paddedUsername = pad(user_name.getBytes(), MAX_USER_LEN);
//		byte[] salt = secureRandomNumber(SALT_LEN);
//		byte[] header = concat(paddedUsername, salt); // 128 + 64 = 192
//
////		byte[] hash = hash_SHA512_Wrapper(password.getBytes()); // 64
//		byte[] hash = hash_SHA512(password.getBytes()); // 64
//
//		byte[] secretData = concat(hash, LEN); // 64 + 16
//		byte[] AESKey = hash2Key(hash);
//		byte[] nonce = secureRandomNumber(NONCE_SIZE);
//		int ctr = Integer.parseInt(META_NAME);
//		byte[] encryptedSecretData = AES_CTR(secretData, AESKey, nonce, ctr);
//
//		byte[] metadata = concat(header, encryptedSecretData); // 96 + 192 = 288
//		metadata = concat(metadata, nonce); // 80 + 16 = 96
//
//		byte[] hmac = hmac_SHA512(AESKey, metadata); // 64
//		
//        save_to_file(concat(metadata, hmac), meta, 0); // 288 + 64 = 352
//
//    }
//
//    /**
//     * Steps to consider... <p> *  
//	 * - check if metadata file size is valid <p> *  
//	 * - get username from metadata <p>
//     */
//    @Override
//    public String findUser(String file_name) throws Exception {
//		File dir = new File(file_name);
//        File meta = new File(dir, "0");
//
//		if (meta.length() != META_SIZE)
//			return "";
//        return new String(read_from_file(meta, 0, MAX_USER_LEN)).trim();
//    }
//
//    /**
//     * Steps to consider...:<p>
//     *  - get password, salt then AES key <p>     
//     *  - decrypt password hash out of encrypted secret data <p>
//     *  - check the equality of the two password hash values <p>
//     *  - decrypt file length out of encrypted secret data
//     */
//    @Override
//    public int length(String file_name, String password) throws Exception {
//		File dir = new File(file_name);
//        File meta = new File(dir, META_NAME);
//
//		byte[] AESKey = hash2Key(hashPassword(dir, password));
//
//		int offset = MAX_USER_LEN + SALT_LEN;
//		int len = HASH_SIZE + LEN.length;
//        byte[] encryptedSecretData = read_from_file(meta, offset, len);
//
//		byte[] secretData = decript_AES(encryptedSecretData, AESKey);
//		byte[] length = new byte[LEN.length];
//
//		for (int i = 0; i < length.length; ++i)
//			length[i] = secretData[i + HASH_SIZE];
//
//		return byteArray2Int(length);
//    }
//
//    /**
//     * Steps to consider...:<p>
//     *  - verify password <p>
//     *  - check if requested starting position and length are valid <p>
//     *  - decrypt content data of requested length 
//     */
//    @Override
//    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
//		File dir = new File(file_name);
//		File meta = new File(dir, META_NAME);
//
//		int file_number = (starting_position / Config.BLOCK_SIZE) + 1;
//
//		byte[] nonce = read_from_file(meta, NONCE_OFFSET, NONCE_SIZE);
//
//		if (file_number <= 0)
//			return null;
//
//        File data = new File(dir, String.valueOf(file_number));
//
//		if (data == null)
//			return null;
//
//		byte[] AESKey = hash2Key(hashPassword(dir, password));
//
//		if (starting_position < 0 || len < 0)
//			return null;
//
//		int offset = starting_position % Config.BLOCK_SIZE;
//		byte[] encryptedData = read_from_file(data, offset, len);
//		return AES_CTR(encryptedData, AESKey, nonce, file_number);
//    }
//
//    
//    /**
//     * Steps to consider...:<p>
//	 *	- verify password <p>
//     *  - check if requested starting position is valid <p>
//     *  - ### main procedure for update the encrypted content ### <p>
//     *  - compute new HMAC and update metadata 
//     */
//    @Override
//    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
//		File dir = new File(file_name);
//
//		int file_number = (starting_position / Config.BLOCK_SIZE) + 1;
//
//		// Must update metadata because of change in nonce
//		byte[] nonce = secureRandomNumber(NONCE_SIZE);
//
//		if (file_number <= 0)
//			return;
//
//        File data = new File(dir, String.valueOf(file_number));
//
//		byte[] hash = hashPassword(dir, password);
//		byte[] AESKey = hash2Key(hash);
//
//		if (starting_position < 0)
//			return;
//		
//		int ctr = file_number * AES_BLOCKS_PER_FILE;
//		byte[] encryptedData = AES_CTR(content, AESKey, nonce, file_number);
//		int offset = starting_position % Config.BLOCK_SIZE;
//		save_to_file(encryptedData, data, offset);
//
//		int newLength = starting_position + content.length;
//		int oldLength = length(file_name, password);
//
//		// Check for append
//		if (newLength > oldLength)
//			updateMetadata(dir, hash, nonce, newLength);
//		else
//			updateMetadata(dir, hash, nonce, oldLength);
//
//    } 
//
//	/**
//     * Steps to consider...:<p>
//  	 *  - verify password <p>
//     *  - check the equality of the computed and stored HMAC values for metadata <p>
//     */
//    @Override
//    public boolean check_integrity(String file_name, String password) throws Exception {
//		File dir = new File(file_name);
//        File meta = new File(dir, META_NAME);
//
//		byte[] AESKey = hash2Key(hashPassword(dir, password));
//
//		byte[] metadata = read_from_file(meta);
//
//		byte[] hmac = read_from_file(meta, HMAC_OFFSET, HMAC_SIZE);
//
//		return byteEquals(hmac, hmac_SHA512(AESKey, metadata));
//	}
//
//    /**
//     * Steps to consider... <p>
//     *  - verify password <p>
//     *  - truncate the content after the specified length <p>
//     *  - re-pad, update metadata and HMAC <p>
//     */
//    @Override
//    public void cut(String file_name, int length, String password) throws Exception {
//		if (length < 0)
//			length = 0;
//
//		File dir = new File(file_name);
//		File meta = new File(dir, META_NAME);
//
//		int lastBlock = length(file_name, password) / Config.BLOCK_SIZE;
//
//		byte[] nonce = read_from_file(meta, NONCE_OFFSET, NONCE_SIZE);	
//
//		byte[] hash = hashPassword(dir, password);	
//
//		int cutBlock = length / Config.BLOCK_SIZE;
//
//		for (int i = cutBlock + 1; i <= lastBlock; ++i) {
//			File del = new File(dir, String.valueOf(i));
//			del.delete();
//		}
//
//		int offset = length % Config.BLOCK_SIZE;
//
//		byte[] content = new byte [Config.BLOCK_SIZE - offset];
//
//		int starting_position = length % Config.BLOCK_SIZE;
//
//		write(String.valueOf(cutBlock), starting_position, content, password);
//
//		updateMetadata(dir, hash, nonce, length);
//    }
//
//	private void updateMetadata(File dir, byte[] hash, byte[] nonce, int length) throws Exception {
//		File meta = new File(dir, META_NAME);
//		byte[] savedData = concat(hash, int2ByteArray(length));
//		byte[] AESKey = hash2Key(hash);
//		int ctr = Integer.parseInt(META_NAME);
//		byte[] encryptedSavedData = AES_CTR(savedData, AESKey, nonce, ctr);
//
//		byte[] metadata = read_from_file(meta, 0, META_SIZE); 
//
//		for (int i = HASH_OFFSET; i < NONCE_OFFSET; ++i)
//			metadata[i] = encryptedSavedData[i - HASH_OFFSET];
//
//		for (int i = NONCE_OFFSET; i < HMAC_OFFSET; ++i)
//			metadata[i] = nonce[i - NONCE_OFFSET];
//		
//		save_to_file(metadata, meta, 0);
//	}
// 
//    /**
//	 *  - Get salt
//	 *  - Calculate hash
//	 *  - Compare hash
//	 */
//   	private byte[] hashPassword(File dir, String password) throws Exception {
//		File meta = new File(dir, META_NAME);
//
//        byte[] salt = read_from_file(meta, MAX_USER_LEN, SALT_LEN);
////		byte[] hash = hash_SHA512_Wrapper(concat(password.getBytes(), salt));
//		byte[] hash = hash_SHA512(concat(password.getBytes(), salt));
//
//		byte[] AESKey = hash2Key(hash);
//		int HASH_START = MAX_USER_LEN + SALT_LEN;
//        byte[] encryptedHash = read_from_file(meta, HASH_START, HASH_SIZE);
//		byte[] hash2 = decript_AES(encryptedHash, AESKey);
//
//		if (!byteEquals(hash, hash2))
//			throw new PasswordIncorrectException();
//
//		return hash;
//	}	
//
//    /**
//	 *  - Truncate hash
//	 */
//	private byte[] hash2Key(byte[] hash) {
//		byte[] key = new byte[AES_KEY_SIZE];
//
//		for (int i = 0; i < key.length; ++i)
//			key[i] = hash[i];
//
//		return key;
//	}
//
//	private boolean byteEquals(byte[] b1, byte[] b2) {
//		if (b1.length != b2.length)
//			return false;
//
//		for (int i = 0; i < b1.length; ++i) {
//			if (b1[i] != b2[i])
//				return false;
//		}
//
//		return true;
//	}    
//	
//	private byte[] hmac_SHA512(byte[] key, byte[] message) throws Exception {
//		byte[] oKeyPad = new byte[SHA512_BLOCKSIZE];
//		byte[] iKeyPad = new byte[SHA512_BLOCKSIZE];
//
//		if (key.length > SHA512_BLOCKSIZE)	
//				key = hash_SHA512(key);
//
//		if (key.length < SHA512_BLOCKSIZE)
//				key = pad(key, SHA512_BLOCKSIZE);
//
//		assert(key.length == oKeyPad.length);
//		assert(key.length == iKeyPad.length);
//
//		for (int i = 0; i < key.length; ++i)
//			oKeyPad[i] = (byte)(key[i] ^ OPAD_VALUE);
//
//		for (int i = 0; i < key.length; ++i)
//			iKeyPad[i] = (byte)(key[i] ^ IPAD_VALUE);
//
////		byte[] innerHash = hash_SHA512_Wrapper(concat(iKeyPad, message));
//		byte[] innerHash = hash_SHA512(concat(iKeyPad, message));
//
////		return hash_SHA512_Wrapper(concat(oKeyPad, innerHash));
//		return hash_SHA512(concat(oKeyPad, innerHash));
//
//    }
//
//	private byte[] pad(byte[] b1, int blockSize) {
//		if (b1.length % blockSize == 0)
//			return b1;
//
//		int padding = blockSize - (b1.length % blockSize); 
//
//		byte[] combined = new byte[b1.length + padding];
//
//		for (int i = 0; i < b1.length; ++i)
//			combined[i] = b1[i];
//
//		return combined;
//	}
//	
//	private byte[] concat(byte[] b1, byte[] b2) {
//		byte[] combined = new byte[b1.length + b2.length];
//
//		for (int i = 0; i < b1.length; ++i)
//			combined[i] = b1[i];
//		for (int i = b1.length; i < b1.length + b2.length; ++i)
//			combined[i] = b2[i-b1.length];
//
//		return combined;
//	}	
//
//    private int byteArray2Int(byte[] array) throws Exception {
//		int val = 0;
//
//		if (array.length > 4)
//			throw new Exception("Too big to fit in int");
//
//        for (int i = 0; i < array.length; i++) {
//            val <<= 8;
//			val |= (array[i] & 0xFF);
//		}
//
//        return val;
//    }	
//
//    private byte[] int2ByteArray(int value) {
//		return new byte[] {
//			(byte)(value >>> 24),
//			(byte)(value >>> 16),
//			(byte)(value >>> 8),
//			(byte)value
//		};
//    }
//
//	/*
//	 *
//	 */
//	private byte[] AES_CTR(byte[] txt, byte[] key, byte[] nonce, int ctr) {
//		if (key.length != AES_KEY_SIZE)
//			return null;
//
//		if (txt.length != AES_BLOCK_SIZE)
//			pad(txt, AES_BLOCK_SIZE);
//
//		byte[] encrypted = new byte[txt.length];
//		byte[] plainText;
//
//		for (int i = 0; i < encrypted.length / AES_BLOCK_SIZE; ++i) {
//			plainText = concat(nonce, int2ByteArray(ctr));
//			try {
//				byte[] keyStr = encript_AES(plainText, key);
//
//				int offset = i * AES_BLOCK_SIZE;
//
//				for (int j = 0; j < AES_BLOCK_SIZE; ++j)
//					encrypted[j + offset] = (byte)(txt[j + offset] ^ keyStr[j]);
//			} catch (Exception e) {
//				return null;
//			} 
//
//			++ctr; // Each block must have different counter
//		}
//
//		return encrypted;
//	}
//	
////  
////	   public byte[] read_from_file(File file, int start_point, int len) throws Exception {
////	       DataInputStream in = new DataInputStream(
////	               new BufferedInputStream(
////	               new FileInputStream(file)));
////
////	       int size = in.available();
////
////	       byte[] toR = new byte[size];
////	       byte[] toReturn = new byte[len];
////
////	       in.read(toR);
////
////	       in.close();
////	       int j = 0;
////	       for (int i = 0; i < len; i++) {
////				j = i + start_point;
////				toReturn[i] = toR[j];
////			}
////	       return toReturn;
////
////	   }
////	   
////
////	   public void save_to_file(byte[] s, File file, int start_point) throws Exception {
////	       if (file == null) {
////	           return;
////	       }
////	       
////	    // create a new RandomAccessFile with filename test
////	       try { 
////	       	RandomAccessFile raf = new RandomAccessFile(file, "rw");
////		        raf.seek(start_point);
////		
////		        for (int i = 0; i < s.length; i++) {
////		        	 raf.writeByte(s[i]);
////				}
////		       
////		        raf.close();
////	       	
////	       }catch (IOException ex) {
////	           ex.printStackTrace();
////	       }
////	      
////	   }
//	 
//    
//   
//}
