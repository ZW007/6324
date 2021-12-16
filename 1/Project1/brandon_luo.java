/**
 * @author Brandon Luo
 * @netid bxl190001
 * @email bxl190001@utdallas.edu
 */

import java.io.File;

public class EFS extends Utility {

	final int SHA512_BLOCKSIZE = 64;
	final byte IPAD_VALUE = 0x36;
	final byte OPAD_VALUE = 0x5c;

	final int AES_BLOCK_SIZE = 16;
	final int AES_KEY_SIZE = 16;
	final int AES_BLOCKS_PER_FILE = Config.BLOCK_SIZE / AES_BLOCK_SIZE;

	final int MAX_PASSWORD_LEN = 128;
	final int MAX_USER_LEN = 128;

	final int SALT_OFFSET = MAX_USER_LEN;
	final int SALT_LEN = 64;

	final int HASH_OFFSET = SALT_OFFSET + SALT_LEN;
	final int HASH_SIZE = SHA512_BLOCKSIZE;

	final int LEN_OFFSET = HASH_OFFSET + HASH_SIZE;
	final int LEN_SIZE = 4;

	final int ENCRYPT_M_OFFSET = HASH_OFFSET;
	final int ENCRYPT_M_SIZE = roundToBlockUp(HASH_SIZE + LEN_SIZE, AES_BLOCK_SIZE);

	final int PADDING_SIZE = ENCRYPT_M_SIZE - (HASH_SIZE + LEN_SIZE);

	final int NONCE_SIZE = 12;
	final int M_NONCE_OFFSET = ENCRYPT_M_OFFSET + ENCRYPT_M_SIZE;

	final int M_HMAC_OFFSET = M_NONCE_OFFSET + NONCE_SIZE;
	final int HMAC_SIZE = SHA512_BLOCKSIZE;

	final String M_NAME = "0";
	final int M_NUM = 0;
	final int M_SIZE = M_HMAC_OFFSET + HMAC_SIZE;
	final int M_BLOCK_SIZE = ceilD(M_SIZE, Config.BLOCK_SIZE);

	final int META_SIZE = roundToBlockUp(NONCE_SIZE + SHA512_BLOCKSIZE, AES_BLOCK_SIZE);

	final int D_SIZE = Config.BLOCK_SIZE - META_SIZE;
	final int D_NONCE_OFFSET = D_SIZE;
	final int D_HMAC_OFFSET = D_NONCE_OFFSET + NONCE_SIZE;

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
		System.out.println("create: " + file_name + " " + user_name);
		if (user_name.length() > MAX_USER_LEN)
			throw new UsernameLengthException();
	    if (password.length() > MAX_PASSWORD_LEN)
			throw new PasswordLengthException();

        dir = new File(file_name);
        dir.mkdirs();
        File meta = new File(dir, M_NAME);

		byte[] salt = secureRandomNumber(SALT_LEN);
		byte[] hash = hash_SHA512_Wrapper(concat(password.getBytes(), salt));
		writeMetadata(dir, user_name, salt, hash, 0);
		System.out.println("create done");
    }

    /**
     * Steps to consider... <p> *  
	 * - check if metadata file size is valid <p> *  
	 * - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
		File dir = new File(file_name);
        File meta = new File(dir, M_NAME);

		System.out.println(meta.getAbsolutePath());
		if (meta.length() != M_SIZE)
			throw new MetadataLengthException();
        return new String(read_from_file(meta, 0, MAX_USER_LEN)).trim();
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
		System.out.println("length: " + file_name);
		File dir = new File(file_name);
        File meta = new File(dir, M_NAME);

		byte[] encrypted = read_from_file(meta, ENCRYPT_M_OFFSET, ENCRYPT_M_SIZE);
		byte[] AESKey = hash2Key(hashPassword(dir, password));
		byte[] nonce = read_from_file(meta, M_NONCE_OFFSET, NONCE_SIZE);
		byte[] decrypted = AES_CTR(encrypted, AESKey, nonce, M_NUM);
		byte[] length = sliceArray(decrypted, HASH_SIZE, LEN_SIZE);
		System.out.println("length done");
		return byteArray2Int(length);
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
		System.out.println("read: " + file_name + " " +  starting_position + " " + len);

		if (starting_position < 0 || len < 0)
			throw new ReadOutOfBoundsException();

		int oldLength = length(file_name, password);
		if (starting_position + len > oldLength)
			throw new ReadOutOfBoundsException();

		int startF = starting_position / Config.BLOCK_SIZE + M_BLOCK_SIZE;
		int endF = (starting_position + len) / Config.BLOCK_SIZE + M_BLOCK_SIZE;
		File dir = new File(file_name);
		byte[] AESKey = hash2Key(hashPassword(dir, password));
		byte[] data = new byte[0];

		for (int fn = startF; fn <= endF; ++fn)
			data = concat(data, readPhysicalFile(fn, AESKey));

		data = sliceArray(data, starting_position % D_SIZE, len);
		System.out.println("Read done");
		return data;
    }

    
    /**
     * Steps to consider...:<p>
	 *	- verify password <p>
     *  - check if requested starting position is valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata 
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
		System.out.println("write: " + file_name + " " + starting_position);
		if (starting_position < 0)
			return;

		int oldLength = length(file_name, password);

		if (starting_position > oldLength) // file must be contiguous
			return;

		int start = starting_position / D_SIZE + M_BLOCK_SIZE;
		int end = (starting_position + content.length) / D_SIZE + M_BLOCK_SIZE;

		if (start <= 0) // Can't write to metadata
			return;

		File dir = new File(file_name);
		byte[] hash = hashPassword(dir, password);
		byte[] AESKey = hash2Key(hash);
		byte[] remainingContent;

		byte[] data = readPhysicalFile(start, AESKey); // Decrypt first file
		if (data != null) {
			int offset = starting_position % D_SIZE;
			for (int i = offset; i < offset + content.length; ++i)
				data[i] = content[i - offset];
			remainingContent = sliceArray2(content, offset + 1);
			System.out.println("Writing to first physical file");
			writePhysicalFile(dir, start, AESKey, data);
			++start;
		} else 
			remainingContent = content;

		byte[][] blocks = splitIntoBlocks(remainingContent, D_SIZE);

		System.out.println("Writing to remaining physical files");
		for (int fn = start; fn <= end; ++fn)
			writePhysicalFile(dir, fn, AESKey, blocks[fn - start]);

		int newLength = starting_position + content.length;
		// Check for append
		if (newLength > oldLength) {
			File meta = new File(dir, M_NAME);
			byte[] salt = read_from_file(meta, SALT_OFFSET, SALT_LEN);
			writeMetadata(dir, findUser(file_name), salt, hash, newLength);
		}

		System.out.println("write done");
    } 

	/**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata <p>
     *  - check the equality of the computed and stored HMAC values for files <p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
		System.out.println("check_integrity: " + file_name);
		File dir = new File(file_name);
        File meta = new File(dir, M_NAME);

		byte[] AESKey = hash2Key(hashPassword(dir, password));
		byte[] metadata = read_from_file(meta, 0, M_HMAC_OFFSET);
		byte[] hmac = read_from_file(meta, M_HMAC_OFFSET, HMAC_SIZE);

		if (!byteEquals(hmac, hmac_SHA512(AESKey, metadata)))
			return false;

		int lastFile = length(file_name, password) / D_SIZE + M_BLOCK_SIZE;
		for (int fn = M_BLOCK_SIZE; fn <= lastFile; ++fn) {
			if (!check_data_integrity(dir, fn, AESKey))
				return false;
		}

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
		System.out.println("cut: " + length);
		if (length < 0)
			length = 0;

		File dir = new File(file_name);
		File meta = new File(dir, M_NAME);

		byte[] hash = hashPassword(dir, password);	
		byte[] AESKey = hash2Key(hash);	

		int cutBlock = length / Config.BLOCK_SIZE + M_BLOCK_SIZE;
		int oldLength = length(file_name, password);
		int lastBlock = oldLength / Config.BLOCK_SIZE + M_BLOCK_SIZE;

		for (int fn = cutBlock + 1; fn <= lastBlock; ++fn) { // Delete blocks
			File del = new File(dir, String.valueOf(fn));
			del.delete();
		}

		byte[] data = readPhysicalFile(cutBlock, AESKey);
		int offset = length % D_SIZE;
		data = sliceArray(data, offset);

		pad(data, D_SIZE);

		write(file_name, cutBlock * D_SIZE, data, password);
		byte[] salt = read_from_file(meta, SALT_OFFSET, SALT_LEN);
		writeMetadata(dir, findUser(file_name), salt, hash, length);

		System.out.println("cut done");
    }

	private void writeMetadata(File dir, String user_name, byte[] salt, byte[] hash, int length) throws Exception {
		File meta = new File(dir, M_NAME);

		byte[] paddedUsername = pad(user_name.getBytes(), MAX_USER_LEN); // 128
		byte[] header = concat(paddedUsername, salt); // 128 + 64 = 192

		byte[] secret = concat(hash, int2ByteArray(length)); // 64 + 4 = 68
		byte[] paddedSecret = pad(secret, AES_BLOCK_SIZE); // 68 -> 80
		byte[] AESKey = hash2Key(hash);
		byte[] nonce = secureRandomNumber(NONCE_SIZE); // Prevent CPA
		byte[] encrypted = AES_CTR(paddedSecret, AESKey, nonce, M_NUM);

		byte[] metadata = concat(header, encrypted); // 192 + 80 = 272
		metadata = concat(metadata, nonce); // 272 + 12 = 284
		byte[] hmac = hmac_SHA512(AESKey, metadata);
		metadata = concat(metadata, hmac); // 284 + 64 = 348
		save_to_file(metadata, meta);
	}
 
    /**
	 *  - Get salt
	 *  - Calculate hash
	 *  - Compare hash
	 */
   	private byte[] hashPassword(File dir, String password) throws Exception {
		File meta = new File(dir, M_NAME);

        byte[] salt = read_from_file(meta, SALT_OFFSET, SALT_LEN);
		byte[] hash = hash_SHA512_Wrapper(concat(password.getBytes(), salt));

        byte[] encrypted = read_from_file(meta, ENCRYPT_M_OFFSET, ENCRYPT_M_SIZE);
		byte[] AESKey = hash2Key(hash);
		byte[] nonce = read_from_file(meta, M_NONCE_OFFSET, NONCE_SIZE);
		byte[] decrypted = AES_CTR(encrypted, AESKey, nonce, M_NUM);
		byte[] hash2 = sliceArray(decrypted, HASH_SIZE);

		if (!byteEquals(hash, hash2))
			throw new PasswordIncorrectException();

		return hash;
	}	

    /**
	 *  Truncate hash
	 *  HASH_SIZE = 64
	 *  AES_KEY_SIZE = 16
	 */
	private byte[] hash2Key(byte[] hash) {
		byte[] key = new byte[AES_KEY_SIZE];

		for (int i = 0; i < key.length; ++i)
			key[i] = hash[i];

		return key;
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
	
	private byte[] hmac_SHA512(byte[] key, byte[] message) {
		byte[] oKeyPad = new byte[SHA512_BLOCKSIZE];
		byte[] iKeyPad = new byte[SHA512_BLOCKSIZE];

		if (key.length > SHA512_BLOCKSIZE)	
				key = hash_SHA512_Wrapper(key);

		if (key.length < SHA512_BLOCKSIZE)
				key = pad(key, SHA512_BLOCKSIZE);

		assert(key.length == oKeyPad.length);
		assert(key.length == iKeyPad.length);

		for (int i = 0; i < key.length; ++i)
			oKeyPad[i] = (byte)(key[i] ^ OPAD_VALUE);

		for (int i = 0; i < key.length; ++i)
			iKeyPad[i] = (byte)(key[i] ^ IPAD_VALUE);

		byte[] innerHash = hash_SHA512_Wrapper(concat(iKeyPad, message));
		return hash_SHA512_Wrapper(concat(oKeyPad, innerHash));
    }

	/**
	 * Pads with null bytes up to next multiple of AES_BLOCK_SIZE
	 */
	private byte[] pad(byte[] b1, int blockSize) {
		if (b1.length % blockSize == 0)
			return b1;

		int padding = blockSize - (b1.length % blockSize); 

		byte[] combined = new byte[b1.length + padding];

		for (int i = 0; i < b1.length; ++i)
			combined[i] = b1[i];

		return combined;
	}
	
	private byte[] concat(byte[] b1, byte[] b2) {
		byte[] combined = new byte[b1.length + b2.length];

		for (int i = 0; i < b1.length; ++i)
			combined[i] = b1[i];

		for (int i = 0; i < b2.length; ++i)
			combined[i + b1.length] = b2[i];

		return combined;
	}	

    private int byteArray2Int(byte[] array) throws Exception {
		int val = 0;

		if (array.length > 4)
			throw new Exception("Too big to fit in int");

        for (int i = 0; i < array.length; ++i) {
            val <<= 8;
			val |= (array[i] & 0xFF);
		}

        return val;
    }	

    private byte[] int2ByteArray(int value) {
		return new byte[] {
			(byte)(value >>> 24),
			(byte)(value >>> 16),
			(byte)(value >>> 8),
			(byte)value
		};
    }

	/*
	 *
	 */
	private byte[] AES_CTR(byte[] txt, byte[] key, byte[] nonce, int ctr) {
		if (key.length != AES_KEY_SIZE) {
			System.out.println("Wrong key size");
			return null;
		}

		if (txt.length % AES_BLOCK_SIZE != 0) {
			System.out.println("Not a multiple of block size");
			return null;
		}

		byte[][] blocks = splitIntoBlocks(txt, AES_BLOCK_SIZE);
		byte[] encrypted = new byte[txt.length];
		byte[] plainText, keyStr;

		for (int bn = 0; bn < blocks.length; ++bn) {
			plainText = concat(nonce, int2ByteArray(ctr)); // 12 + 4 
			try {
				keyStr = encript_AES(plainText, key);
			} catch (Exception e) {
				System.out.println(e.getMessage());
				return null;
			} 
			int offset = bn * AES_BLOCK_SIZE;

			for (int i = 0; i < AES_BLOCK_SIZE; ++i)
				encrypted[i + offset] = (byte)(txt[i + offset] ^ keyStr[i]);

			++ctr; // Each block must have different counter
		}

		return encrypted;
	}

	private byte[] hash_SHA512_Wrapper(byte[] message) {
		try {
			return hash_SHA512(message);
		} catch (Exception e) {
			System.out.println("hash_SHA512_Wrapper" + e.getMessage());
			return null;
		}
	}

	private byte[][] splitIntoBlocks(byte[] array, int blockSize) {
		if (blockSize <= 0)
			return null;

		byte[] paddedArray = pad(array, blockSize);
		int numBlocks = paddedArray.length / blockSize;
		byte[][] split = new byte[numBlocks][blockSize];

		for (int i = 0; i < numBlocks; ++i) {
			for (int j = 0; j < blockSize; ++j)
				split[i][j] = paddedArray[i * blockSize + j];
		}

		return split;
	}

	private int ceilD(int dividend, int divisor) {
		int isRem = (dividend % divisor != 0) ? 1 : 0;
		return (dividend / divisor) + isRem;
	}

	/*
	 * Returns first part of byte array sliced at pos
	 * Does not include element at pos
	 */
	private byte[] sliceArray(byte[] array, int pos) {
		if (pos >= array.length)
			return null;

		byte[] sliced = new byte[pos];
		for (int i = 0; i < pos; ++i)
			sliced[i] = array[i];

		return sliced;
	}

	/*
	 * Returns second part of byte array sliced at pos
	 * Includes element at pos
	 */
	private byte[] sliceArray2(byte[] array, int pos) {
		if (pos >= array.length)
			return null;

		byte[] sliced = new byte[array.length - pos];
		for (int i = 0; i < sliced.length; ++i)
			sliced[i] = array[i + pos];

		return sliced;
	}

	/*
	 * Returns byte array beginning at start with length len
	 * [start, start + len)
	 */
	private byte[] sliceArray(byte[] array, int start, int len) {
		if (start < 0)
			return null;
		if (start + len >= array.length)
			return null;

		byte[] sliced = new byte[len];
		for (int i = start; i < start + len; ++i)
			sliced[i - start] = array[i];

		return sliced;
	}

	/*
	 * Rounds up to nearest multiple of blockSize
	 */
	private int roundToBlockUp(int num, int blockSize) {
		int quotient = num / blockSize;
		int isRem = (num % blockSize != 0) ? 1 : 0;
		return (quotient + isRem) * blockSize;
	}

	private void printArray(String name, byte[] array) {
		System.out.print(name + ": ");
		for (int i = 0; i < array.length; ++i)
			System.out.print(array[i] + " ");
		System.out.println("");
	}
	
	/*
	 * Converts logical position to file number
	 */
	private int logPosToFn(int logPos) {
		return logPos / D_SIZE + M_BLOCK_SIZE;	
	}

	private byte[] readPhysicalFile(int fn, byte[] AESKey) throws Exception {
		System.out.println("readPhysicalFile: " + fn);

		File f = new File(dir, String.valueOf(fn));
		if (!f.isFile())
			return null;
		byte[] encrypted = read_from_file(f, 0, D_SIZE);
		byte[] nonce = read_from_file(f, D_NONCE_OFFSET, NONCE_SIZE);
		return AES_CTR(encrypted, AESKey, nonce, 0);
	}

	private void writePhysicalFile(File dir, int fn, byte[] AESKey, byte[] data) throws Exception {
		System.out.println("writePhysicalFile: " + fn);

		if (data.length != D_SIZE)
			throw new InvalidWriteException();

		File f = new File(dir, String.valueOf(fn));
		byte[] nonce = secureRandomNumber(NONCE_SIZE); // Prevent CPA
		byte[] encrypted = AES_CTR(data, AESKey, nonce, 0);
		byte[] metadata = concat(encrypted, nonce);
		byte[] hmac = hmac_SHA512(AESKey, metadata);
		metadata = pad(concat(metadata, hmac), Config.BLOCK_SIZE);
		save_to_file(metadata, f);
	}

	private boolean check_data_integrity(File dir, int fn, byte[] AESKey) {
		System.out.println("check_data_integrity: " + fn);
		File f = new File(dir, String.valueOf(fn));
		byte[] encrypted = read_from_file(f, 0, D_SIZE);
		byte[] nonce = read_from_file(f, D_NONCE_OFFSET, NONCE_SIZE);
		byte[] metadata = concat(encrypted, nonce);
		byte[] hmac = hmac_SHA512(AESKey, metadata);
		byte[] hmac2 = read_from_file(f, D_HMAC_OFFSET, HMAC_SIZE);
		return byteEquals(hmac, hmac2);
	}
}



// /**
//  * @author Brandon Luo
//  * @netid bxl190001
//  * @email bxl190001@utdallas.edu
//  */

// // From Sample
// import java.io.File;

// public class EFS extends Utility {

// 	final int SHA512_BLOCKSIZE = 64;
// 	final byte IPAD_VALUE = 0x36;
// 	final byte OPAD_VALUE = 0x5c;

// 	final int AES_BLOCK_SIZE = 16;
// 	final int AES_KEY_SIZE = 16;
// 	final int AES_BLOCKS_PER_FILE = Config.BLOCK_SIZE / AES_BLOCK_SIZE;

// 	final int MAX_PASSWORD_LEN = 128;
// 	final int MAX_USER_LEN = 128;

// 	final int SALT_LEN = 64;
// 	final int SALT_OFFSET = MAX_USER_LEN;

// 	final int HASH_OFFSET = SALT_OFFSET + SALT_LEN;
// 	final int HASH_SIZE = SHA512_BLOCKSIZE;

// 	final byte[] LEN = new byte[16]; // Initialized with 0
// 	final int LEN_OFFSET = HASH_OFFSET + HASH_SIZE;

// 	final int NONCE_SIZE = 4;
// 	final int NONCE_OFFSET = LEN_OFFSET + LEN.length;

// 	final int HMAC_OFFSET = NONCE_OFFSET + NONCE_SIZE;
// 	final int HMAC_SIZE = SHA512_BLOCKSIZE;

// 	final String META_NAME = "0";
// 	final int META_SIZE = HMAC_OFFSET + HMAC_SIZE;

//     public EFS(Editor e)
//     {
//         super(e);
//         set_username_password();
//     }

   
//     /**
//      * Steps to consider... <p>
//      *  - add padded username and password salt to header <p>
//      *  - add password hash and file length to secret data <p>
//      *  - AES encrypt padded secret data <p>
//      *  - add header and encrypted secret data to metadata <p>
//      *  - compute HMAC for integrity check of metadata <p>
//      *  - add metadata and HMAC to metadata file block <p>
//      */
//     @Override
//     public void create(String file_name, String user_name, String password) throws Exception {
// 		if (user_name.length() > MAX_USER_LEN)
// 			throw new UsernameLengthException();
// 	    if (password.length() > MAX_PASSWORD_LEN)
// 			throw new PasswordLengthException();

//         dir = new File(file_name);
//         dir.mkdirs();
//         File meta = new File(dir, META_NAME);

// 		byte[] paddedUsername = pad(user_name.getBytes(), MAX_USER_LEN);
// 		byte[] salt = secureRandomNumber(SALT_LEN);
// 		byte[] header = concat(paddedUsername, salt); // 128 + 64 = 192

// 		byte[] hash = hash_SHA512_Wrapper(password.getBytes()); // 64
// 		byte[] secretData = concat(hash, LEN); // 64 + 16
// 		byte[] AESKey = hash2Key(hash);
// 		byte[] nonce = secureRandomNumber(NONCE_SIZE);
// 		int ctr = Integer.parseInt(META_NAME);
// 		byte[] encryptedSecretData = AES_CTR(secretData, AESKey, nonce, ctr);

// 		byte[] metadata = concat(header, encryptedSecretData); // 96 + 192 = 288
// 		metadata = concat(metadata, nonce); // 80 + 16 = 96

// 		byte[] hmac = hmac_SHA512(AESKey, metadata); // 64

//         save_to_file(concat(metadata, hmac), meta); // 288 + 64 = 352
//     }

//     /**
//      * Steps to consider... <p> *  
// 	 * - check if metadata file size is valid <p> *  
// 	 * - get username from metadata <p>
//      */
//     @Override
//     public String findUser(String file_name) throws Exception {
// 		File dir = new File(file_name);
//         File meta = new File(dir, "0");

// 		if (meta.length() != META_SIZE)
// 			return "";
//         return new String(read_from_file(meta, 0, MAX_USER_LEN)).trim();
//     }

//     /**
//      * Steps to consider...:<p>
//      *  - get password, salt then AES key <p>     
//      *  - decrypt password hash out of encrypted secret data <p>
//      *  - check the equality of the two password hash values <p>
//      *  - decrypt file length out of encrypted secret data
//      */
//     @Override
//     public int length(String file_name, String password) throws Exception {
// 		File dir = new File(file_name);
//         File meta = new File(dir, META_NAME);

// 		byte[] AESKey = hash2Key(hashPassword(dir, password));

// 		int offset = MAX_USER_LEN + SALT_LEN;
// 		int len = HASH_SIZE + LEN.length;
//         byte[] encryptedSecretData = read_from_file(meta, offset, len);

// 		byte[] secretData = decript_AES(encryptedSecretData, AESKey);
// 		byte[] length = new byte[LEN.length];

// 		for (int i = 0; i < length.length; ++i)
// 			length[i] = secretData[i + HASH_SIZE];

// 		return byteArray2Int(length);
//     }

//     /**
//      * Steps to consider...:<p>
//      *  - verify password <p>
//      *  - check if requested starting position and length are valid <p>
//      *  - decrypt content data of requested length 
//      */
//     @Override
//     public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
// 		File dir = new File(file_name);
// 		File meta = new File(dir, META_NAME);

// 		int file_number = (starting_position / Config.BLOCK_SIZE) + 1;

// 		byte[] nonce = read_from_file(meta, NONCE_OFFSET, NONCE_SIZE);

// 		if (file_number <= 0)
// 			return null;

//         File data = new File(dir, String.valueOf(file_number));

// 		if (data == null)
// 			return null;

// 		byte[] AESKey = hash2Key(hashPassword(dir, password));

// 		if (starting_position < 0 || len < 0)
// 			return null;

// 		int offset = starting_position % Config.BLOCK_SIZE;
// 		byte[] encryptedData = read_from_file(data, offset, len);
// 		return AES_CTR(encryptedData, AESKey, nonce, file_number);
//     }

    
//     /**
//      * Steps to consider...:<p>
// 	 *	- verify password <p>
//      *  - check if requested starting position is valid <p>
//      *  - ### main procedure for update the encrypted content ### <p>
//      *  - compute new HMAC and update metadata 
//      */
//     @Override
//     public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
// 		File dir = new File(file_name);

// 		int file_number = (starting_position / Config.BLOCK_SIZE) + 1;

// 		// Must update metadata because of change in nonce
// 		byte[] nonce = secureRandomNumber(NONCE_SIZE);

// 		if (file_number <= 0)
// 			return;

//         File data = new File(dir, String.valueOf(file_number));

// 		byte[] hash = hashPassword(dir, password);
// 		byte[] AESKey = hash2Key(hash);

// 		if (starting_position < 0)
// 			return;
		
// 		int ctr = file_number * AES_BLOCKS_PER_FILE;
// 		byte[] encryptedData = AES_CTR(content, AESKey, nonce, file_number);
// 		int offset = starting_position % Config.BLOCK_SIZE;
// 		save_to_file(encryptedData, data, offset);

// 		int newLength = starting_position + content.length;
// 		int oldLength = length(file_name, password);

// 		// Check for append
// 		if (newLength > oldLength)
// 			updateMetadata(dir, hash, nonce, newLength);
// 		else
// 			updateMetadata(dir, hash, nonce, oldLength);

//     } 

// 	/**
//      * Steps to consider...:<p>
//   	 *  - verify password <p>
//      *  - check the equality of the computed and stored HMAC values for metadata <p>
//      */
//     @Override
//     public boolean check_integrity(String file_name, String password) throws Exception {
// 		File dir = new File(file_name);
//         File meta = new File(dir, META_NAME);

// 		byte[] AESKey = hash2Key(hashPassword(dir, password));

// 		byte[] metadata = read_from_file(meta);

// 		byte[] hmac = read_from_file(meta, HMAC_OFFSET, HMAC_SIZE);

// 		return byteEquals(hmac, hmac_SHA512(AESKey, metadata));
// 	}

//     /**
//      * Steps to consider... <p>
//      *  - verify password <p>
//      *  - truncate the content after the specified length <p>
//      *  - re-pad, update metadata and HMAC <p>
//      */
//     @Override
//     public void cut(String file_name, int length, String password) throws Exception {
// 		if (length < 0)
// 			length = 0;

// 		File dir = new File(file_name);
// 		File meta = new File(dir, META_NAME);

// 		int lastBlock = length(file_name, password) / Config.BLOCK_SIZE;

// 		byte[] nonce = read_from_file(meta, NONCE_OFFSET, NONCE_SIZE);	

// 		byte[] hash = hashPassword(dir, password);	

// 		int cutBlock = length / Config.BLOCK_SIZE;

// 		for (int i = cutBlock + 1; i <= lastBlock; ++i) {
// 			File del = new File(dir, String.valueOf(i));
// 			del.delete();
// 		}

// 		int offset = length % Config.BLOCK_SIZE;

// 		byte[] content = new byte [Config.BLOCK_SIZE - offset];

// 		int starting_position = length % Config.BLOCK_SIZE;

// 		write(String.valueOf(cutBlock), starting_position, content, password);

// 		updateMetadata(dir, hash, nonce, length);
//     }

// 	private void updateMetadata(File dir, byte[] hash, byte[] nonce, int length) {
// 		File meta = new File(dir, META_NAME);
// 		byte[] savedData = concat(hash, int2ByteArray(length));
// 		byte[] AESKey = hash2Key(hash);
// 		int ctr = Integer.parseInt(META_NAME);
// 		byte[] encryptedSavedData = AES_CTR(savedData, AESKey, nonce, ctr);

// 		byte[] metadata = read_from_file(meta, 0, META_SIZE); 

// 		for (int i = HASH_OFFSET; i < NONCE_OFFSET; ++i)
// 			metadata[i] = encryptedSavedData[i - HASH_OFFSET];

// 		for (int i = NONCE_OFFSET; i < HMAC_OFFSET; ++i)
// 			metadata[i] = nonce[i - NONCE_OFFSET];
		
// 		save_to_file(metadata, meta, 0);
// 	}
 
//     /**
// 	 *  - Get salt
// 	 *  - Calculate hash
// 	 *  - Compare hash
// 	 */
//    	private byte[] hashPassword(File dir, String password) throws Exception {
// 		File meta = new File(dir, META_NAME);

//         byte[] salt = read_from_file(meta, MAX_USER_LEN, SALT_LEN);
// 		byte[] hash = hash_SHA512_Wrapper(concat(password.getBytes(), salt));
// 		byte[] AESKey = hash2Key(hash);
// 		int HASH_START = MAX_USER_LEN + SALT_LEN;
//         byte[] encryptedHash = read_from_file(meta, HASH_START, HASH_SIZE);
// 		byte[] hash2 = decript_AES(encryptedHash, AESKey);

// 		if (!byteEquals(hash, hash2))
// 			throw new PasswordIncorrectException();

// 		return hash;
// 	}	

//     /**
// 	 *  - Truncate hash
// 	 */
// 	private byte[] hash2Key(byte[] hash) {
// 		byte[] key = new byte[AES_KEY_SIZE];

// 		for (int i = 0; i < key.length; ++i)
// 			key[i] = hash[i];

// 		return key;
// 	}

// 	private boolean byteEquals(byte[] b1, byte[] b2) {
// 		if (b1.length != b2.length)
// 			return false;

// 		for (int i = 0; i < b1.length; ++i) {
// 			if (b1[i] != b2[i])
// 				return false;
// 		}

// 		return true;
// 	}    
	
// 	private byte[] hmac_SHA512(byte[] key, byte[] message) {
// 		byte[] oKeyPad = new byte[SHA512_BLOCKSIZE];
// 		byte[] iKeyPad = new byte[SHA512_BLOCKSIZE];

// 		if (key.length > SHA512_BLOCKSIZE)	
// 				key = hash_SHA512_Wrapper(key);

// 		if (key.length < SHA512_BLOCKSIZE)
// 				key = pad(key, SHA512_BLOCKSIZE);

// 		assert(key.length == oKeyPad.length);
// 		assert(key.length == iKeyPad.length);

// 		for (int i = 0; i < key.length; ++i)
// 			oKeyPad[i] = (byte)(key[i] ^ OPAD_VALUE);

// 		for (int i = 0; i < key.length; ++i)
// 			iKeyPad[i] = (byte)(key[i] ^ IPAD_VALUE);

// 		byte[] innerHash = hash_SHA512_Wrapper(concat(iKeyPad, message));
// 		return hash_SHA512_Wrapper(concat(oKeyPad, innerHash));
//     }

// 	private byte[] pad(byte[] b1, int blockSize) {
// 		if (b1.length % blockSize == 0)
// 			return b1;

// 		int padding = blockSize - (b1.length % blockSize); 

// 		byte[] combined = new byte[b1.length + padding];

// 		for (int i = 0; i < b1.length; ++i)
// 			combined[i] = b1[i];

// 		return combined;
// 	}
	
// 	private byte[] concat(byte[] b1, byte[] b2) {
// 		byte[] combined = new byte[b1.length + b2.length];

// 		for (int i = 0; i < b1.length; ++i)
// 			combined[i] = b1[i];
// 		for (int i = b1.length; i < b1.length + b2.length; ++i)
// 			combined[i] = b2[i-b1.length];

// 		return combined;
// 	}	

//     private int byteArray2Int(byte[] array) throws Exception {
// 		int val = 0;

// 		if (array.length > 4)
// 			throw new Exception("Too big to fit in int");

//         for (int i = 0; i < array.length; i++) {
//             val <<= 8;
// 			val |= (array[i] & 0xFF);
// 		}

//         return val;
//     }	

//     private byte[] int2ByteArray(int value) {
// 		return new byte[] {
// 			(byte)(value >>> 24),
// 			(byte)(value >>> 16),
// 			(byte)(value >>> 8),
// 			(byte)value
// 		};
//     }

// 	/*
// 	 *
// 	 */
// 	private byte[] AES_CTR(byte[] txt, byte[] key, byte[] nonce, int ctr) {
// 		if (key.length != AES_KEY_SIZE)
// 			return null;

// 		if (txt.length != AES_BLOCK_SIZE)
// 			pad(txt, AES_BLOCK_SIZE);

// 		byte[] encrypted = new byte[txt.length];
// 		byte[] plainText;

// 		for (int i = 0; i < encrypted.length / AES_BLOCK_SIZE; ++i) {
// 			plainText = concat(nonce, int2ByteArray(ctr));
// 			try {
// 				byte[] keyStr = encript_AES(plainText, key);

// 				int offset = i * AES_BLOCK_SIZE;

// 				for (int j = 0; j < AES_BLOCK_SIZE; ++j)
// 					encrypted[j + offset] = (byte)(txt[j + offset] ^ keyStr[j]);
// 			} catch (Exception e) {
// 				return null;
// 			} 

// 			++ctr; // Each block must have different counter
// 		}

// 		return encrypted;
// 	}
// }



import java.io.File;

public class EFS extends Utility {

	final int SHA512_BLOCKSIZE = 64;
	final byte IPAD_VALUE = 0x36;
	final byte OPAD_VALUE = 0x5c;

	final int AES_BLOCK_SIZE = 16;
	final int AES_KEY_SIZE = 16;
	final int AES_BLOCKS_PER_FILE = Config.BLOCK_SIZE / AES_BLOCK_SIZE;

	final int MAX_PASSWORD_LEN = 128;
	final int MAX_USER_LEN = 128;

	final int SALT_OFFSET = MAX_USER_LEN;
	final int SALT_LEN = 64;

	final int HASH_OFFSET = SALT_OFFSET + SALT_LEN;
	final int HASH_SIZE = SHA512_BLOCKSIZE;

	final int LEN_OFFSET = HASH_OFFSET + HASH_SIZE;
	final int LEN_SIZE = 4;

	final int ENCRYPT_M_OFFSET = HASH_OFFSET;
	final int ENCRYPT_M_SIZE = roundToBlockUp(HASH_SIZE + LEN_SIZE, AES_BLOCK_SIZE);

	final int PADDING_SIZE = ENCRYPT_M_SIZE - (HASH_SIZE + LEN_SIZE);

	final int NONCE_SIZE = 12;
	final int M_NONCE_OFFSET = ENCRYPT_M_OFFSET + ENCRYPT_M_SIZE;

	final int M_HMAC_OFFSET = M_NONCE_OFFSET + NONCE_SIZE;
	final int HMAC_SIZE = SHA512_BLOCKSIZE;

	final String M_NAME = "0";
	final int M_NUM = 0;
	final int M_SIZE = M_HMAC_OFFSET + HMAC_SIZE;
	final int M_BLOCK_SIZE = ceilD(M_SIZE, Config.BLOCK_SIZE);

	final int META_SIZE = roundToBlockUp(NONCE_SIZE + SHA512_BLOCKSIZE, AES_BLOCK_SIZE);

	final int D_SIZE = Config.BLOCK_SIZE - META_SIZE;
	final int D_NONCE_OFFSET = D_SIZE;
	final int D_HMAC_OFFSET = D_NONCE_OFFSET + NONCE_SIZE;

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
		System.out.println("create: " + file_name + " " + user_name);
		
        dir = new File(file_name);
        dir.mkdirs();
        File meta = new File(dir, M_NAME);

		byte[] salt = secureRandomNumber(SALT_LEN);
		byte[] hash = hash_SHA512_Wrapper(concat(password.getBytes(), salt));
		writeMetadata(dir, user_name, salt, hash, 0);
		System.out.println("create done");
    }

    /**
     * Steps to consider... <p> *  
	 * - check if metadata file size is valid <p> *  
	 * - get username from metadata <p>
     */
    @Override
    public String findUser(String file_name) throws Exception {
		File dir = new File(file_name);
        File meta = new File(dir, M_NAME);

		System.out.println(meta.getAbsolutePath());
		
        return new String(read_from_file(meta, 0, MAX_USER_LEN)).trim();
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
		System.out.println("length: " + file_name);
		File dir = new File(file_name);
        File meta = new File(dir, M_NAME);

		byte[] encrypted = read_from_file(meta, ENCRYPT_M_OFFSET, ENCRYPT_M_SIZE);
		byte[] AESKey = hash2Key(hashPassword(dir, password));
		byte[] nonce = read_from_file(meta, M_NONCE_OFFSET, NONCE_SIZE);
		byte[] decrypted = AES_CTR(encrypted, AESKey, nonce, M_NUM);
		byte[] length = sliceArray(decrypted, HASH_SIZE, LEN_SIZE);
		System.out.println("length done");
		return byteArray2Int(length);
    }

    /**
     * Steps to consider...:<p>
     *  - verify password <p>
     *  - check if requested starting position and length are valid <p>
     *  - decrypt content data of requested length 
     */
    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
		System.out.println("read: " + file_name + " " +  starting_position + " " + len);

		int oldLength = length(file_name, password);

		int startF = starting_position / Config.BLOCK_SIZE + M_BLOCK_SIZE;
		int endF = (starting_position + len) / Config.BLOCK_SIZE + M_BLOCK_SIZE;
		File dir = new File(file_name);
		byte[] AESKey = hash2Key(hashPassword(dir, password));
		byte[] data = new byte[0];

		for (int fn = startF; fn <= endF; ++fn)
			data = concat(data, readPhysicalFile(fn, AESKey));

		data = sliceArray(data, starting_position % D_SIZE, len);
		System.out.println("Read done");
		return data;
    }

    
    /**
     * Steps to consider...:<p>
	 *	- verify password <p>
     *  - check if requested starting position is valid <p>
     *  - ### main procedure for update the encrypted content ### <p>
     *  - compute new HMAC and update metadata 
     */
    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
		System.out.println("write: " + file_name + " " + starting_position);
		if (starting_position < 0)
			return;

		int oldLength = length(file_name, password);

		if (starting_position > oldLength) // file must be contiguous
			return;

		int start = starting_position / D_SIZE + M_BLOCK_SIZE;
		int end = (starting_position + content.length) / D_SIZE + M_BLOCK_SIZE;

		if (start <= 0) // Can't write to metadata
			return;

		File dir = new File(file_name);
		byte[] hash = hashPassword(dir, password);
		byte[] AESKey = hash2Key(hash);
		byte[] remainingContent;

		byte[] data = readPhysicalFile(start, AESKey); // Decrypt first file
		if (data != null) {
			int offset = starting_position % D_SIZE;
			for (int i = offset; i < offset + content.length; ++i)
				data[i] = content[i - offset];
			remainingContent = sliceArray2(content, offset + 1);
			System.out.println("Writing to first physical file");
			writePhysicalFile(dir, start, AESKey, data);
			++start;
		} else 
			remainingContent = content;

		byte[][] blocks = splitIntoBlocks(remainingContent, D_SIZE);

		System.out.println("Writing to remaining physical files");
		for (int fn = start; fn <= end; ++fn)
			writePhysicalFile(dir, fn, AESKey, blocks[fn - start]);

		int newLength = starting_position + content.length;
		// Check for append
		if (newLength > oldLength) {
			File meta = new File(dir, M_NAME);
			byte[] salt = read_from_file(meta, SALT_OFFSET, SALT_LEN);
			writeMetadata(dir, findUser(file_name), salt, hash, newLength);
		}

		System.out.println("write done");
    } 

	/**
     * Steps to consider...:<p>
  	 *  - verify password <p>
     *  - check the equality of the computed and stored HMAC values for metadata <p>
     *  - check the equality of the computed and stored HMAC values for files <p>
     */
    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {
		System.out.println("check_integrity: " + file_name);
		File dir = new File(file_name);
        File meta = new File(dir, M_NAME);

		byte[] AESKey = hash2Key(hashPassword(dir, password));
		byte[] metadata = read_from_file(meta, 0, M_HMAC_OFFSET);
		byte[] hmac = read_from_file(meta, M_HMAC_OFFSET, HMAC_SIZE);

		if (!byteEquals(hmac, hmac_SHA512(AESKey, metadata)))
			return false;

		int lastFile = length(file_name, password) / D_SIZE + M_BLOCK_SIZE;
		for (int fn = M_BLOCK_SIZE; fn <= lastFile; ++fn) {
			if (!check_data_integrity(dir, fn, AESKey))
				return false;
		}

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
		System.out.println("cut: " + length);
		if (length < 0)
			length = 0;

		File dir = new File(file_name);
		File meta = new File(dir, M_NAME);

		byte[] hash = hashPassword(dir, password);	
		byte[] AESKey = hash2Key(hash);	

		int cutBlock = length / Config.BLOCK_SIZE + M_BLOCK_SIZE;
		int oldLength = length(file_name, password);
		int lastBlock = oldLength / Config.BLOCK_SIZE + M_BLOCK_SIZE;

		for (int fn = cutBlock + 1; fn <= lastBlock; ++fn) { // Delete blocks
			File del = new File(dir, String.valueOf(fn));
			del.delete();
		}

		byte[] data = readPhysicalFile(cutBlock, AESKey);
		int offset = length % D_SIZE;
		data = sliceArray(data, offset);

		pad(data, D_SIZE);

		write(file_name, cutBlock * D_SIZE, data, password);
		byte[] salt = read_from_file(meta, SALT_OFFSET, SALT_LEN);
		writeMetadata(dir, findUser(file_name), salt, hash, length);

		System.out.println("cut done");
    }

	private void writeMetadata(File dir, String user_name, byte[] salt, byte[] hash, int length) throws Exception {
		File meta = new File(dir, M_NAME);

		byte[] paddedUsername = pad(user_name.getBytes(), MAX_USER_LEN); // 128
		byte[] header = concat(paddedUsername, salt); // 128 + 64 = 192

		byte[] secret = concat(hash, int2ByteArray(length)); // 64 + 4 = 68
		byte[] paddedSecret = pad(secret, AES_BLOCK_SIZE); // 68 -> 80
		byte[] AESKey = hash2Key(hash);
		byte[] nonce = secureRandomNumber(NONCE_SIZE); // Prevent CPA
		byte[] encrypted = AES_CTR(paddedSecret, AESKey, nonce, M_NUM);

		byte[] metadata = concat(header, encrypted); // 192 + 80 = 272
		metadata = concat(metadata, nonce); // 272 + 12 = 284
		byte[] hmac = hmac_SHA512(AESKey, metadata);
		metadata = concat(metadata, hmac); // 284 + 64 = 348
		save_to_file(metadata, meta);
	}
 
	   /**
		 *  - Get salt
		 *  - Calculate hash
		 *  - Compare hash
		 */
   	private byte[] hashPassword(File dir, String password) throws Exception {
		File meta = new File(dir, M_NAME);

        byte[] salt = read_from_file(meta, SALT_OFFSET, SALT_LEN);
		byte[] hash = hash_SHA512_Wrapper(concat(password.getBytes(), salt));

        byte[] encrypted = read_from_file(meta, ENCRYPT_M_OFFSET, ENCRYPT_M_SIZE);
		byte[] AESKey = hash2Key(hash);
		byte[] nonce = read_from_file(meta, M_NONCE_OFFSET, NONCE_SIZE);
		byte[] decrypted = AES_CTR(encrypted, AESKey, nonce, M_NUM);
		byte[] hash2 = sliceArray(decrypted, HASH_SIZE);

		if (!byteEquals(hash, hash2))
			throw new PasswordIncorrectException();

		return hash;
	}	

    /**
	 *  Truncate hash
	 *  HASH_SIZE = 64
	 *  AES_KEY_SIZE = 16
	 */
	private byte[] hash2Key(byte[] hash) {
		byte[] key = new byte[AES_KEY_SIZE];

		for (int i = 0; i < key.length; ++i)
			key[i] = hash[i];

		return key;
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
	
	private byte[] hmac_SHA512(byte[] key, byte[] message) {
		byte[] oKeyPad = new byte[SHA512_BLOCKSIZE];
		byte[] iKeyPad = new byte[SHA512_BLOCKSIZE];

		if (key.length > SHA512_BLOCKSIZE)	
				key = hash_SHA512_Wrapper(key);

		if (key.length < SHA512_BLOCKSIZE)
				key = pad(key, SHA512_BLOCKSIZE);

		assert(key.length == oKeyPad.length);
		assert(key.length == iKeyPad.length);

		for (int i = 0; i < key.length; ++i)
			oKeyPad[i] = (byte)(key[i] ^ OPAD_VALUE);

		for (int i = 0; i < key.length; ++i)
			iKeyPad[i] = (byte)(key[i] ^ IPAD_VALUE);

		byte[] innerHash = hash_SHA512_Wrapper(concat(iKeyPad, message));
		return hash_SHA512_Wrapper(concat(oKeyPad, innerHash));
    }

	/**
	 * Pads with null bytes up to next multiple of AES_BLOCK_SIZE
	 */
	private byte[] pad(byte[] b1, int blockSize) {
		if (b1.length % blockSize == 0)
			return b1;

		int padding = blockSize - (b1.length % blockSize); 

		byte[] combined = new byte[b1.length + padding];

		for (int i = 0; i < b1.length; ++i)
			combined[i] = b1[i];

		return combined;
	}
	
	private byte[] concat(byte[] b1, byte[] b2) {
		byte[] combined = new byte[b1.length + b2.length];

		for (int i = 0; i < b1.length; ++i)
			combined[i] = b1[i];

		for (int i = 0; i < b2.length; ++i)
			combined[i + b1.length] = b2[i];

		return combined;
	}	

    private int byteArray2Int(byte[] array) throws Exception {
		int val = 0;

		if (array.length > 4)
			throw new Exception("Too big to fit in int");

        for (int i = 0; i < array.length; ++i) {
            val <<= 8;
			val |= (array[i] & 0xFF);
		}

        return val;
    }	

    private byte[] int2ByteArray(int value) {
		return new byte[] {
			(byte)(value >>> 24),
			(byte)(value >>> 16),
			(byte)(value >>> 8),
			(byte)value
		};
    }

	/*
	 *
	 */
	private byte[] AES_CTR(byte[] txt, byte[] key, byte[] nonce, int ctr) {
		if (key.length != AES_KEY_SIZE) {
			System.out.println("Wrong key size");
			return null;
		}

		if (txt.length % AES_BLOCK_SIZE != 0) {
			System.out.println("Not a multiple of block size");
			return null;
		}

		byte[][] blocks = splitIntoBlocks(txt, AES_BLOCK_SIZE);
		byte[] encrypted = new byte[txt.length];
		byte[] plainText, keyStr;

		for (int bn = 0; bn < blocks.length; ++bn) {
			plainText = concat(nonce, int2ByteArray(ctr)); // 12 + 4 
			try {
				keyStr = encript_AES(plainText, key);
			} catch (Exception e) {
				System.out.println(e.getMessage());
				return null;
			} 
			int offset = bn * AES_BLOCK_SIZE;

			for (int i = 0; i < AES_BLOCK_SIZE; ++i)
				encrypted[i + offset] = (byte)(txt[i + offset] ^ keyStr[i]);

			++ctr; // Each block must have different counter
		}

		return encrypted;
	}

	private byte[] hash_SHA512_Wrapper(byte[] message) {
		try {
			return hash_SHA512(message);
		} catch (Exception e) {
			System.out.println("hash_SHA512_Wrapper" + e.getMessage());
			return null;
		}
	}

	private byte[][] splitIntoBlocks(byte[] array, int blockSize) {
		if (blockSize <= 0)
			return null;

		byte[] paddedArray = pad(array, blockSize);
		int numBlocks = paddedArray.length / blockSize;
		byte[][] split = new byte[numBlocks][blockSize];

		for (int i = 0; i < numBlocks; ++i) {
			for (int j = 0; j < blockSize; ++j)
				split[i][j] = paddedArray[i * blockSize + j];
		}

		return split;
	}

	private int ceilD(int dividend, int divisor) {
		int isRem = (dividend % divisor != 0) ? 1 : 0;
		return (dividend / divisor) + isRem;
	}

	/*
	 * Returns first part of byte array sliced at pos
	 * Does not include element at pos
	 */
	private byte[] sliceArray(byte[] array, int pos) {
		if (pos >= array.length)
			return null;

		byte[] sliced = new byte[pos];
		for (int i = 0; i < pos; ++i)
			sliced[i] = array[i];

		return sliced;
	}

	/*
	 * Returns second part of byte array sliced at pos
	 * Includes element at pos
	 */
	private byte[] sliceArray2(byte[] array, int pos) {
		if (pos >= array.length)
			return null;

		byte[] sliced = new byte[array.length - pos];
		for (int i = 0; i < sliced.length; ++i)
			sliced[i] = array[i + pos];

		return sliced;
	}

	/*
	 * Returns byte array beginning at start with length len
	 * [start, start + len)
	 */
	private byte[] sliceArray(byte[] array, int start, int len) {
		if (start < 0)
			return null;
		if (start + len >= array.length)
			return null;

		byte[] sliced = new byte[len];
		for (int i = start; i < start + len; ++i)
			sliced[i - start] = array[i];

		return sliced;
	}

	/*
	 * Rounds up to nearest multiple of blockSize
	 */
	private int roundToBlockUp(int num, int blockSize) {
		int quotient = num / blockSize;
		int isRem = (num % blockSize != 0) ? 1 : 0;
		return (quotient + isRem) * blockSize;
	}

	private void printArray(String name, byte[] array) {
		System.out.print(name + ": ");
		for (int i = 0; i < array.length; ++i)
			System.out.print(array[i] + " ");
		System.out.println("");
	}
	
	/*
	 * Converts logical position to file number
	 */
	private int logPosToFn(int logPos) {
		return logPos / D_SIZE + M_BLOCK_SIZE;	
	}

	private byte[] readPhysicalFile(int fn, byte[] AESKey) throws Exception {
		System.out.println("readPhysicalFile: " + fn);

		File f = new File(dir, String.valueOf(fn));
		if (!f.isFile())
			return null;
		byte[] encrypted = read_from_file(f, 0, D_SIZE);
		byte[] nonce = read_from_file(f, D_NONCE_OFFSET, NONCE_SIZE);
		return AES_CTR(encrypted, AESKey, nonce, 0);
	}

	private void writePhysicalFile(File dir, int fn, byte[] AESKey, byte[] data) throws Exception {
		System.out.println("writePhysicalFile: " + fn);

		

		File f = new File(dir, String.valueOf(fn));
		byte[] nonce = secureRandomNumber(NONCE_SIZE); // Prevent CPA
		byte[] encrypted = AES_CTR(data, AESKey, nonce, 0);
		byte[] metadata = concat(encrypted, nonce);
		byte[] hmac = hmac_SHA512(AESKey, metadata);
		metadata = pad(concat(metadata, hmac), Config.BLOCK_SIZE);
		save_to_file(metadata, f);
	}

	private boolean check_data_integrity(File dir, int fn, byte[] AESKey) {
		System.out.println("check_data_integrity: " + fn);
		File f = new File(dir, String.valueOf(fn));
		byte[] encrypted = read_from_file(f, 0, D_SIZE);
		byte[] nonce = read_from_file(f, D_NONCE_OFFSET, NONCE_SIZE);
		byte[] metadata = concat(encrypted, nonce);
		byte[] hmac = hmac_SHA512(AESKey, metadata);
		byte[] hmac2 = read_from_file(f, D_HMAC_OFFSET, HMAC_SIZE);
		return byteEquals(hmac, hmac2);
	}
}
