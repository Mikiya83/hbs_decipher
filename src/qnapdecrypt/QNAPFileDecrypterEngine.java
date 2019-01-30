package qnapdecrypt;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.zip.InflaterInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * Engine to decipher operations on QNAP-ciphered files.
 */
public class QNAPFileDecrypterEngine {

	/**
	 * Internal class for encrypted header informations.
	 * 
	 */
	private class EncryptHeader {
		long size;
		private byte[] ckey;
		private byte[] salt;

		public byte[] getCkey() {
			return ckey;
		}

		public byte[] getSalt() {
			return salt;
		}

		public long getSize() {
			return size;
		}

		public void setCkey(byte[] ckey) {
			this.ckey = ckey;
		}

		public void setSalt(byte[] salt) {
			this.salt = salt;
		}

		public void setSize(long size) {
			this.size = size;
		}
	}

	/**
	 * Internal class for file type informations.
	 * 
	 */
	private class FileType {
		final private boolean compressed;
		final private int encryptVersion;

		public FileType(int encryptVersion) {
			this(encryptVersion, false);
		}

		public FileType(int encryptVersion, boolean compressed) {
			this.encryptVersion = encryptVersion;
			this.compressed = compressed;
		}

		public int getEncryptVersion() {
			return encryptVersion;
		}

		public boolean isCompressed() {
			return compressed;
		}
	}

	private static final int AES_KEY_STRENGTH = 256;

	private static final String AES_MODE = "AES/CBC/PKCS5Padding";

	private static final String AES_MODE_HEADER = "AES/ECB/NoPadding";

	private static final int BLOCK_SIZE = 16;

	private static final String DIGEST_ALGO = "MD5";

	private static final String HEADER_EMPTY_VALUE = "\\x00";

	private static final String HEADER_SEPARATOR = "\\x03";

	private static final String HEADER_SPLIT_VALUE = ":";

	private static final int HEADER_V2_LENGTH = 80;

	private static final int PBKDF2_ITER_COUNT = 1000;

	private static final byte[] QNAP_FILE_PREFIX_BYTES = new byte[] { 95, 95, 81, 67, 83, 95, 95 };

	private static final byte[] QNAP_FILE_PREFIX_V2_BYTES_COMPRESS = new byte[] { 75, -54, -108, 114, 94, -125, 28, 49,
			1, 1 };

	private static final byte[] QNAP_FILE_PREFIX_V2_BYTES_NO_COMPRESS = new byte[] { 75, -54, -108, 114, 94, -125, 28,
			49, 1, 0 };

	private static final String TEMP_SUFFIX = ".temp";

	private boolean dirMode = false;

	private boolean verboseMode = false;

	public QNAPFileDecrypterEngine(boolean verbose, boolean dirMode) {
		this.dirMode = dirMode;
		this.verboseMode = verbose;
	}

	/**
	 * Manage decipher operations on file or directory.
	 * 
	 * @param cipherFile
	 *            Ciphered file or directory.
	 * @param plainFile
	 *            Plain file or directory.
	 * @param password
	 *            User defined password.
	 */
	public boolean doDecipherFile(File cipherFile, File plainFile, String password) {
		try {
			cipherFile = cipherFile.getAbsoluteFile();
			if (!cipherFile.canRead()) {
				System.err.println("The file " + cipherFile.getAbsolutePath() + " does not exist or is not readable.");
				return false;
			}

			FileType fileInfos = checkCipheredFile(cipherFile);
			if (fileInfos.getEncryptVersion() < 0) {
				if (dirMode) {
					if (verboseMode) {
						// In dir mode, do not warn about all files not
						// "QNAP-files" if not verbose
						System.out.println("The file " + cipherFile.getName() + " is not a QNAP-ciphered file.");
					}
				} else {
					// In single mode, file must be "QNAP-file"
					System.err.println("The file " + cipherFile.getName() + " is not a QNAP-ciphered file.");
				}
				return false;
			}

			if (verboseMode) {
				System.out.println("Reading header values...");
			}
			if (fileInfos.getEncryptVersion() == 1) {
				if (verboseMode) {
					System.out.println("Read file version 1 !");
				}
				String salt = searchValueInFile(cipherFile, "salt");
				String keyCiphered = searchValueInFile(cipherFile, "key");
				if (verboseMode) {
					System.out.println("Key derivation from password...");
				}
				SecretKeySpec uniqueKey = getPBKDF2Key(password, salt);
				if (verboseMode) {
					System.out.println("Decipher file key...");
				}
				byte[] key = decipherText(Base64.decodeBase64(keyCiphered), uniqueKey);
				// TODO : SecretKeySpec throw a DestroyFailedException as
				// implementation of destroy, use it when a real implementation
				// is done
				uniqueKey = null;
				if (verboseMode) {
					System.out.println("Decipher file...");
				}
				decipherFile(key, new byte[] {}, cipherFile, plainFile, fileInfos);
				Arrays.fill(key, Byte.MAX_VALUE);
				if (verboseMode) {
					System.out.println("Checking checksums from origin and output files...");
				}
				boolean decipherSuccess = compareChecksums(cipherFile, salt, plainFile);
				if (!decipherSuccess) {
					System.err.println("Wrong md5 checksum after decipher !");
				} else if (verboseMode) {
					System.out.println("Checksums ok, decipher " + cipherFile.getName() + " successfull !");
				}
			} else if (fileInfos.getEncryptVersion() == 2) {
				if (verboseMode) {
					System.out.println("Read file version 2 !");
				}
				EncryptHeader eHeader = decipherHeader(cipherFile, password);

				if (verboseMode) {
					System.out.println("Decipher file...");
				}
				decipherFile(eHeader.getCkey(), eHeader.getSalt(), cipherFile, plainFile, fileInfos);
				eHeader.setCkey(null);

				boolean decipherSuccess = (plainFile.length() == eHeader.getSize());
				if (!decipherSuccess) {
					System.err.println("Wrong size after decipher !");
				} else if (verboseMode) {
					System.out.println("Sizes ok, decipher " + cipherFile.getName() + " successfull !");
				}
			}
		} catch (GeneralSecurityException | IOException e) {
			System.err.println("Error occured for file " + cipherFile.getName() + ", check your password.");
			if (verboseMode) {
				e.printStackTrace();
			}
			return false;
		}
		return true;
	}

	public void setDirMode(boolean dirMode) {
		this.dirMode = dirMode;
	}

	/**
	 * Check if the ciphered file is a QNAP-ciphered file.
	 * 
	 * @param file
	 */
	private FileType checkCipheredFile(File cipherFile) {
		try (final FileInputStream inputStream = new FileInputStream(cipherFile)) {

			// affect read buffer and check size
			byte[] readBytes = new byte[Math.max(
					Math.max(QNAP_FILE_PREFIX_BYTES.length, QNAP_FILE_PREFIX_V2_BYTES_NO_COMPRESS.length),
					QNAP_FILE_PREFIX_V2_BYTES_COMPRESS.length)];
			if (cipherFile.length() < readBytes.length) {
				return new FileType(-1);
			}

			// Read in bytes to avoid encoding errors
			inputStream.read(readBytes);
			boolean compressEnable = false;

			// Compare with known headers
			int version = -1;
			if (readBytes.length >= QNAP_FILE_PREFIX_BYTES.length) {
				for (int index = 0; index < readBytes.length; index++) {
					if (QNAP_FILE_PREFIX_BYTES[index] != readBytes[index]) {
						break;
					} else if (index == QNAP_FILE_PREFIX_BYTES.length - 1) {
						version = 1;
					}
				}
			}
			if (version < 0 && readBytes.length >= QNAP_FILE_PREFIX_V2_BYTES_NO_COMPRESS.length) {
				for (int index = 0; index < readBytes.length; index++) {
					if (QNAP_FILE_PREFIX_V2_BYTES_NO_COMPRESS[index] != readBytes[index]) {
						break;
					} else if (index == QNAP_FILE_PREFIX_V2_BYTES_NO_COMPRESS.length - 1) {
						version = 2;
					}
				}
			}
			if (version < 0 && readBytes.length >= QNAP_FILE_PREFIX_V2_BYTES_COMPRESS.length) {
				for (int index = 0; index < readBytes.length; index++) {
					if (QNAP_FILE_PREFIX_V2_BYTES_COMPRESS[index] != readBytes[index]) {
						break;
					} else if (index == QNAP_FILE_PREFIX_V2_BYTES_COMPRESS.length - 1) {
						version = 2;
						compressEnable = true;
					}
				}
			}
			return new FileType(version, compressEnable);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return new FileType(-1);
	}

	/**
	 * Compare checksums from both files.
	 * 
	 * @param cipherFile
	 *            Cipher file to test.
	 * @param digestKey
	 *            Key for decipher the checksum from cipher file.
	 * @param plainFile
	 *            Plain file to test.
	 * @return
	 */
	private boolean compareChecksums(File cipherFile, String digestKey, File plainFile) {
		boolean checksumFail = true;
		try {
			String checksumOriginCiphered = searchValueInFile(cipherFile, "digest");
			SecretKeySpec saltAsKey = new SecretKeySpec(Hex.decodeHex(digestKey.toCharArray()), "AES");
			byte[] checksumOriginPlain = decipherText(Base64.decodeBase64(checksumOriginCiphered), saltAsKey);
			byte[] calculatedPlainChecksum = getChecksum(plainFile);
			for (int checksumIndex = 0; checksumIndex < checksumOriginPlain.length; checksumIndex++) {
				if (checksumOriginPlain[checksumIndex] != calculatedPlainChecksum[checksumIndex]) {
					checksumFail = false;
					break;
				}
			}
		} catch (IOException | GeneralSecurityException | DecoderException e) {
			e.printStackTrace();
		}
		return !checksumFail;
	}

	/**
	 * Decipher a file.
	 * 
	 * @param keyArray
	 * @param salt
	 * @param inputFile
	 * @param outputFile
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	private void decipherFile(byte[] keyArray, byte[] iv, final File inputFile, final File outputFile,
			FileType fileInfo) throws GeneralSecurityException, IOException {

		try {
			// Create files streams
			final FileInputStream inputStream = new FileInputStream(inputFile);
			final FileOutputStream outputStream;
			if (fileInfo.isCompressed()) {
				outputStream = new FileOutputStream(outputFile.getAbsolutePath() + TEMP_SUFFIX);
			} else {
				outputStream = new FileOutputStream(outputFile);
			}

			if (fileInfo.getEncryptVersion() == 1) {
				// Skip file header
				int lengthToSkip = searchDataIndexInFile(inputFile);
				inputStream.skip(lengthToSkip);
			} else if (fileInfo.getEncryptVersion() == 2) {
				// Skip file header
				inputStream.skip(HEADER_V2_LENGTH);
			}
			// Create key
			Cipher dcipher = Cipher.getInstance(AES_MODE);

			// Read random initialization vector.
			if (fileInfo.getEncryptVersion() == 1) {
				iv = new byte[BLOCK_SIZE];
				inputStream.read(iv);
			}
			final IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Initialize decipher
			SecretKeySpec key = new SecretKeySpec(keyArray, "AES");
			// Configure the cipher with the key and the iv.
			dcipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

			// Read data
			int blockSize = dcipher.getBlockSize() * dcipher.getBlockSize();
			int outputSize = dcipher.getOutputSize(blockSize);

			// Fix ShortBufferException problem on Android with OpenSSL Provider like
			// described here :
			// https://blog.osom.info/2014/07/symmetric-encryption-issue-in-android-43.html
			if (dcipher.getProvider().getName().contains("AndroidOpenSSL")) {
				outputSize += dcipher.getBlockSize();
			}

			byte[] inBytes = new byte[blockSize];
			byte[] outBytes = new byte[outputSize];

			if (verboseMode) {
				System.err.println("Use provider : " + dcipher.getProvider().getName() + " - Use block cipher size : "
						+ dcipher.getBlockSize() + " - Use Inputt buffer block size : " + blockSize
						+ " - Use Output buffer size : " + outputSize);
			}

			int inLength = 0;
			boolean done = false;

			while (!done) {
				inLength = inputStream.read(inBytes);
				if (inLength == blockSize) {
					try {
						int outLength = dcipher.update(inBytes, 0, blockSize, outBytes);
						outputStream.write(outBytes, 0, outLength);
					} catch (ShortBufferException e) {
						e.printStackTrace();
					}
				} else
					done = true;
			}

			try {
				if (inLength > 0)
					outBytes = dcipher.doFinal(inBytes, 0, inLength);
				else
					outBytes = dcipher.doFinal();
				outputStream.write(outBytes);
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
			} catch (BadPaddingException e) {
				e.printStackTrace();
			}

			inputStream.close();
			outputStream.flush();
			outputStream.close();

			if (fileInfo.isCompressed()) {
				if (verboseMode) {
					System.out.println("Deciphering ok, decompress file...");
				}
				try (InflaterInputStream in = new InflaterInputStream(
						new FileInputStream(outputFile.getAbsolutePath() + TEMP_SUFFIX))) {
					try (FileOutputStream out = new FileOutputStream(outputFile)) {
						byte[] buffer = new byte[blockSize];
						int len;
						while ((len = in.read(buffer)) != -1) {
							out.write(buffer, 0, len);
						}
					}
				}
			}
		} catch (final GeneralSecurityException exc) {
			throw exc;
		} finally {
			File outputEndFile = new File(outputFile.getAbsolutePath() + TEMP_SUFFIX);
			if (outputEndFile.exists()) {
				outputEndFile.delete();
			}
		}
	}

	/**
	 * Decipher a header text.
	 * 
	 * @param textToDecipher
	 * @param key
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	private EncryptHeader decipherHeader(final File inputFile, String keyPass)
			throws GeneralSecurityException, IOException {

		EncryptHeader eHeader = new EncryptHeader();

		try {
			// Create files streams
			final FileInputStream inputStream = new FileInputStream(inputFile);

			// Skip file header : 16
			inputStream.read(new byte[16]);
			// Create key
			Cipher dcipher = Cipher.getInstance(AES_MODE_HEADER);

			// Initialize decipher
			int iter = Math.round((1 + 32 / keyPass.length()));
			StringBuilder builder = new StringBuilder();
			for (int index = 0; index < iter; index++) {
				builder.append(keyPass);
			}
			// Extract 32 characters from derivated password
			String passwordFinal = builder.toString().substring(0, 32);
			SecretKeySpec key = new SecretKeySpec(passwordFinal.getBytes(), "AES");
			// Configure the cipher with the key and the iv.
			dcipher.init(Cipher.DECRYPT_MODE, key);

			// Read data
			byte[] inBytes = new byte[64];
			byte[] outBytes = new byte[64];
			inputStream.read(inBytes);
			outBytes = dcipher.doFinal(inBytes);
			inputStream.close();

			final ByteArrayInputStream inputHeaderStream = new ByteArrayInputStream(outBytes);
			DataInputStream packed = new DataInputStream(inputHeaderStream);

			// Struct is : magic [8] + ckey[32] + salt [16] + size [8]
			byte[] magic = new byte[8];
			byte[] ckey = new byte[32];
			byte[] salt = new byte[16];
			byte[] size = new byte[8];

			// Read magic but do not use it
			packed.read(magic, 0, 8);

			packed.read(ckey, 0, 32);
			eHeader.setCkey(ckey);

			packed.read(salt, 0, 16);
			eHeader.setSalt(salt);

			packed.read(size, 0, 8);
			// ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
			ByteBuffer buffer = ByteBuffer.allocate(Long.SIZE / Byte.SIZE);
			buffer.put(size);
			buffer.flip();// need flip
			eHeader.setSize(buffer.getLong());

			packed.close();
			inputHeaderStream.close();

		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

		return eHeader;
	}

	/**
	 * Decipher a text.
	 * 
	 * @param textToDecipher
	 * @param key
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	private byte[] decipherText(byte[] textToDecipher, SecretKeySpec key) throws GeneralSecurityException, IOException {

		try {
			Cipher dcipher = Cipher.getInstance(AES_MODE);

			// Read random initialization vector.
			final byte[] iv = Arrays.copyOfRange(textToDecipher, 0, BLOCK_SIZE);
			final IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Configure the cipher with the key and the iv.
			dcipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
			final byte[] textToDecipherWithoutIv = Arrays.copyOfRange(textToDecipher, BLOCK_SIZE,
					textToDecipher.length);

			final byte[] outputBytes = dcipher.doFinal(textToDecipherWithoutIv);
			return outputBytes;

		} catch (final GeneralSecurityException exc) {
			throw exc;
		}
	}

	/**
	 * Calculate the file checksum.
	 * 
	 * @param file
	 * @return The file checksum.
	 * @throws NoSuchAlgorithmException
	 */
	private byte[] getChecksum(File file) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(DIGEST_ALGO);
		try (InputStream is = new FileInputStream(file); DigestInputStream dis = new DigestInputStream(is, md)) {
			/* Read decorated stream (dis) to EOF as normal... */
		} catch (IOException e) {
			e.printStackTrace();
		}
		return md.digest();
	}

	/**
	 * Get PBKDF2 from password and salt.
	 * 
	 * @param pwd
	 * @param salt
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	private SecretKeySpec getPBKDF2Key(String pwd, String salt) {

		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			byte[] saltValue = Hex.decodeHex(salt.toCharArray());
			KeySpec spec = new PBEKeySpec(pwd.toCharArray(), saltValue, PBKDF2_ITER_COUNT, AES_KEY_STRENGTH);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKeySpec key = new SecretKeySpec(tmp.getEncoded(), "AES");
			return key;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (DecoderException e) {
			e.printStackTrace();
		}
		return null;

	}

	/**
	 * Search the index in file for data (after the header).
	 * 
	 * @param file
	 */
	private int searchDataIndexInFile(File file) {
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			char[] readBuffer = new char[1024];
			br.read(readBuffer);

			String readString = new String(readBuffer);
			String[] keys = readString.split(HEADER_SEPARATOR);

			// Search for delimiter index after last property (digest)
			int index = 0;
			int countEmpty = 0;

			boolean lastPropertyFound = false;
			for (int stringIndex = 0; stringIndex < keys.length; stringIndex++) {
				String eachKey = keys[stringIndex];
				if (!lastPropertyFound) {
					index += eachKey.length() + 1;
				}
				String[] keyAndValue = eachKey.split(HEADER_SPLIT_VALUE);
				if (keyAndValue.length == 2) {
					if ("digest".equals(keyAndValue[0])) {
						lastPropertyFound = true;
					}
					if (lastPropertyFound) {
						// Count number of empty character at the
						// beginning of data
						String dataStart = keys[stringIndex + 1];
						for (int dataIndex = 0; dataIndex < dataStart.length(); dataIndex++) {
							if (dataStart.substring(dataIndex, dataIndex + 1).matches("^" + HEADER_EMPTY_VALUE)) {
								countEmpty++;
							} else {
								break;
							}
						}
						index += countEmpty;
						return index;
					}
				}
			}

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return -1;
	}

	/**
	 * Search the value in file for a header key.
	 * 
	 * @param file
	 * @param inputSearch
	 */
	private String searchValueInFile(File file, String inputSearch) {
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			char[] readBuffer = new char[1024];
			br.read(readBuffer);
			try {
				String readString = new String(readBuffer);
				String[] keys = readString.split(HEADER_SEPARATOR);
				for (String eachKey : keys) {
					String[] keyAndValue = eachKey.split(HEADER_SPLIT_VALUE);
					if (keyAndValue.length == 2) {
						if (inputSearch.equals(keyAndValue[0])) {
							return keyAndValue[1];
						}
					}
				}
				br.read(readBuffer);
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return "";
	}

}
