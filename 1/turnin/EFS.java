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
