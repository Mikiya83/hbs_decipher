package qnapdecrypt;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * Class to request decipher QNAP ciphered files.
 */

public class QNAPFileDecrypter {

	private static final int AES_KEY_STRENGTH = 256;

	private static final String CIPHERED_FILE_OPTION = "i";

	private static boolean dirMode = false;

	private static final String JAVA_7_JCE = "http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html";

	private static final String JAVA_7_VERSION = "1.7";

	private static final String JAVA_8_JCE = "http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html";

	private static final String JAVA_8_VERSION = "1.8";

	private static final String PASSWORD_OPTION = "p";

	private static final String PLAIN_FILE_OPTION = "o";

	private static final String PLAIN_NAME_PREFIX = "plain_";

	private static final String RECURSIVE_OPTION = "r";

	private static boolean recursiveMode = false;

	private static final String TOOL_VERSION = "1.6";

	private static final String VERBOSE_OPTION = "v";

	private static boolean verboseMode = false;

	/**
	 * Main program to decipher a file ciphered in QNAP Backup utility.
	 * 
	 * @param password
	 * @param pathInputFile
	 * @param pathOutputFile
	 */
	public static void main(String[] args) {

		final String applicationName = "QNAPFileDecrypter";
		if (args.length < 1) {
			displayHeader(System.out);
			displayHelpAndExit(applicationName);
		}
		CommandLine commandlineOptions = usePosixParser(args);

		// Verify options
		try {
			if (!commandlineOptions.hasOption(CIPHERED_FILE_OPTION)
					|| !commandlineOptions.hasOption(PLAIN_FILE_OPTION)) {
				displayHeader(System.out);
				displayHelpAndExit(applicationName);
			}
		} catch (Exception e) {
			displayHeader(System.out);
			displayHelpAndExit(applicationName);
		}

		if (commandlineOptions.hasOption(VERBOSE_OPTION)) {
			verboseMode = true;
		}

		if (commandlineOptions.hasOption(RECURSIVE_OPTION)) {
			recursiveMode = true;
		}

		if (verboseMode) {
			// Header
			displayHeader(System.out);
		}

		// Check required JCE
		try {
			if (verboseMode) {
				System.out.println("Check JCE policy...");
			}
			boolean jceApplied = false;
			try {
				// try the property after update 151
				Security.setProperty("crypto.policy", "unlimited");
				if (Cipher.getMaxAllowedKeyLength("AES") >= AES_KEY_STRENGTH) {
					// Update applied so property can be set !
					jceApplied = true;
				}
			} catch (SecurityException exc) {
				// Cannot write permission, do not crash on it it can be normal,
				// try to override JCE file next
			} catch (NoSuchAlgorithmException exc2) {
				System.err.println("JAVA version not supported, AES missing.");
				System.exit(1);
			}

			if (Cipher.getMaxAllowedKeyLength("AES") < AES_KEY_STRENGTH && !jceApplied) {
				String linkJCE = "Link not found for JCE policy";
				if (System.getProperty("java.version").startsWith(JAVA_7_VERSION)) {
					linkJCE = JAVA_7_JCE;
				} else if (System.getProperty("java.version").startsWith(JAVA_8_VERSION)) {
					linkJCE = JAVA_8_JCE;
				} else {
					System.err.println("JAVA version not supported, install JCE policy on JRE 7 / 8.");
					System.exit(1);
				}
				System.err.println(System.lineSeparator()
						+ "Required JCE policy not installed, use this for your version : " + System.lineSeparator()
						+ linkJCE + System.lineSeparator() + "Instructions are provided in the JCE archive.");
				System.exit(1);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
		}

		File cipherFile = new File(commandlineOptions.getOptionValue(CIPHERED_FILE_OPTION));
		File plainFile = new File(commandlineOptions.getOptionValue(PLAIN_FILE_OPTION));

		if (cipherFile.exists() && cipherFile.isDirectory()) {
			// To be able to decipher a directory, plain parameter must be a
			// directory too
			if (plainFile.exists() && plainFile.isDirectory()) {
				dirMode = true;
				if (verboseMode) {
					System.out.println("Entering in directory mode.");
				}
			} else {
				displayHelpAndExit(applicationName);
			}
		}

		String password;
		if (!commandlineOptions.hasOption(PASSWORD_OPTION)) {
			Console console = System.console();
			if (console == null) {
				System.out.println("Couldn't get Console instance");
				displayHelpAndExit(applicationName);
			}
			char[] passwordChars = console.readPassword("Enter user password : ");
			password = new String(passwordChars);
			Arrays.fill(passwordChars, ' ');

			if (password == null || password.isEmpty()) {
				System.err.println("No password entered.");
				displayHelpAndExit(applicationName);
			}
		} else {
			password = commandlineOptions.getOptionValue(PASSWORD_OPTION);
		}

		QNAPFileDecrypterEngine engine = new QNAPFileDecrypterEngine(verboseMode, dirMode);

		if (!dirMode) {
			// Single file mode
			File outputFile = plainFile;
			if (plainFile.isDirectory()) {
				if (plainFile.equals(cipherFile.getParentFile())) {
					if (cipherFile.getName().endsWith(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION)) {
						outputFile = new File(plainFile + File.separator + PLAIN_NAME_PREFIX
								+ cipherFile.getName().replaceAll(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION, ""));
					} else {
						outputFile = new File(plainFile + File.separator + PLAIN_NAME_PREFIX + cipherFile.getName());
					}
				} else {
					if (cipherFile.getName().endsWith(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION)) {
						outputFile = new File(plainFile + File.separator
								+ cipherFile.getName().replaceAll(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION, ""));
					} else {
						outputFile = new File(plainFile + File.separator + cipherFile.getName());
					}
				}
			} else if (cipherFile.equals(plainFile)) {
				if (cipherFile.getName().endsWith(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION)) {
					outputFile = new File(plainFile.getParent() + File.separator + PLAIN_NAME_PREFIX
							+ cipherFile.getName().replaceAll(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION, ""));
				} else {
					outputFile = new File(
							plainFile.getParent() + File.separator + PLAIN_NAME_PREFIX + cipherFile.getName());
				}
			}
			engine.doDecipherFile(cipherFile, outputFile, password);
		} else {
			decipherMultipleFiles(cipherFile, plainFile, password, engine);
		}
	}

	/**
	 * Construct and provide Posix-compatible Options.
	 * 
	 * @return Options expected from command-line of Posix form.
	 */
	private static Options constructPosixOptions() {
		final Options posixOptions = new Options();
		posixOptions.addOption(
				Option.builder(VERBOSE_OPTION).desc("Enable verbose mode").hasArg(false).required(false).build());
		posixOptions.addOption(
				Option.builder(PASSWORD_OPTION).desc("User defined password").hasArg(true).required(false).build());
		posixOptions.addOption(Option.builder(CIPHERED_FILE_OPTION)
				.desc("Input ciphered file (or directory) to decipher").hasArg(true).required(true).build());
		posixOptions.addOption(Option.builder(PLAIN_FILE_OPTION).desc("Output plain file (or directory)").hasArg(true)
				.required(true).build());
		posixOptions.addOption(
				Option.builder(RECURSIVE_OPTION).desc("Enable recursive mode (WARNING : MAY TAKE A LONG TIME !)")
						.hasArg(false).required(false).build());

		return posixOptions;
	}

	private static void decipherMultipleFiles(File cipherFile, File plainFile, String password,
			QNAPFileDecrypterEngine engine) {
		File cipherDir = cipherFile;
		File plainDir = plainFile;

		String[] cipheredListFiles = cipherDir.list();
		for (String eachCipheredFileName : cipheredListFiles) {

			String eachPlainFileName = eachCipheredFileName;
			if (cipherDir.equals(plainDir)) {
				if (eachCipheredFileName.endsWith(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION)) {
					eachPlainFileName = PLAIN_NAME_PREFIX
							+ eachCipheredFileName.replaceAll(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION, "");
				} else {
					eachPlainFileName = PLAIN_NAME_PREFIX + eachCipheredFileName;
				}
			} else if (eachPlainFileName.endsWith(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION)) {
				eachPlainFileName = eachCipheredFileName.replaceAll(QNAPFileDecrypterEngine.QNAP_BZ2_EXTENSION, "");
			}
			File eachCipherFile = new File(cipherDir + File.separator + eachCipheredFileName);
			File eachPlainFile = new File(plainDir + File.separator + eachPlainFileName);

			// Check recursive mode
			if (recursiveMode && eachCipherFile.isDirectory() && eachCipherFile.canRead()) {
				if (verboseMode) {
					System.out.println(System.lineSeparator() + "Enter in directory : " + eachCipheredFileName);
				}
				String newPlainDir = plainDir + File.separator + eachPlainFileName;
				String newCipherDir = cipherDir + File.separator + eachCipheredFileName;
				try {
					if (!Files.isDirectory(Paths.get(newPlainDir))) {
						Files.createDirectory(Paths.get(newPlainDir));
					}
					decipherMultipleFiles(new File(newCipherDir), new File(newPlainDir), password, engine);
				} catch (IOException e) {
					System.out.println("Cannot create directory for recursive mode.");
				}
			} else {
				if (verboseMode) {
					System.out.println(System.lineSeparator() + "Trying to decipher file : " + eachCipheredFileName);
				}
				if (!eachCipherFile.isDirectory() && eachCipherFile.canRead()) {
					engine.doDecipherFile(eachCipherFile, eachPlainFile, password);
				} else {
					if (verboseMode) {
						System.out.println("Skiping : " + eachCipheredFileName);
					}
				}
			}
		}
	}

	/**
	 * Display application header.
	 * 
	 * @out OutputStream to which header should be written.
	 */
	private static void displayHeader(final OutputStream out) {
		System.out.print(System.lineSeparator());
		final String header = "[NOT-OFFICIAL file decipher for QNAP Hybrid Backup Sync files V" + TOOL_VERSION + "]";
		try {
			out.write(header.getBytes());
		} catch (IOException ioEx) {
			System.out.println(header);
		}
		System.out.println(System.lineSeparator());
	}

	/**
	 * Display application help and exit.
	 * 
	 * @out applicationName
	 */
	private static void displayHelpAndExit(final String applicationName) {
		System.out.println("-- HELP --");
		printHelp(constructPosixOptions(), 80, "COMMAND HELP", System.lineSeparator()
				+ "Note : in directory mode, both input and output arguments must be directories. Decipher operation is not recursive."
				+ System.lineSeparator() + "END OF HELP", 3, 5, true, System.out);

		System.exit(1);
	}

	/**
	 * Write "help" to the provided OutputStream.
	 */
	private static void printHelp(final Options options, final int printedRowWidth, final String header,
			final String footer, final int spacesBeforeOption, final int spacesBeforeOptionDescription,
			final boolean displayUsage, final OutputStream out) {
		final String commandLineSyntax = "java -jar qnap_decrypt_XXX.jar";
		final PrintWriter writer = new PrintWriter(out);
		final HelpFormatter helpFormatter = new HelpFormatter();
		helpFormatter.printHelp(writer, printedRowWidth, commandLineSyntax, header, options, spacesBeforeOption,
				spacesBeforeOptionDescription, footer, displayUsage);
		writer.close();
	}

	/**
	 * Apply Apache Commons CLI PosixParser to command-line arguments.
	 * 
	 * @param commandLineArguments
	 *            Command-line arguments to be processed with Posix-style parser.
	 */
	private static CommandLine usePosixParser(final String[] commandLineArguments) {
		final CommandLineParser cmdLinePosixParser = new DefaultParser();
		final Options posixOptions = constructPosixOptions();
		try {
			return cmdLinePosixParser.parse(posixOptions, commandLineArguments);
		} catch (ParseException parseException) {
			System.err
					.println("Encountered exception while parsing using PosixParser:\n" + parseException.getMessage());
		}
		return null;
	}
}
