package com.ibayad.pgp;

import com.ibayad.pgp.model.DecryptionRequest;
import com.ibayad.pgp.model.EncryptionRequest;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import java.io.*;

@SpringBootApplication
@RestController
public class PgpApplication {

	private static final String ENCRYPTION_ALGORITHM = "DES";

	public static void main(String[] args) {
		SpringApplication.run(PgpApplication.class, args);
		System.out.println(new EncryptionRequest().getKey());
	}

	@PostMapping("/encrypt")
	public ResponseEntity<byte[]> encryptCSVFile(@RequestParam("plaintextFile") MultipartFile plaintextFile,
												 @RequestParam("encryptionKey") String encryptionKey) {
		if (plaintextFile.isEmpty()) {
			return ResponseEntity.badRequest().body(null);
		}

		try (InputStream plaintextInputStream = plaintextFile.getInputStream();
			 ByteArrayOutputStream encryptedOutputStream = new ByteArrayOutputStream()) {

			// Generate SecretKey from provided key
			SecretKey secretKey = generateSecretKey(encryptionKey);

			// Create the cipher and initialize it for encryption
			Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);

			// Create a CipherOutputStream to encrypt the data
			CipherOutputStream cipherOutputStream = new CipherOutputStream(encryptedOutputStream, cipher);

			// Read plaintext data from the input stream and write encrypted data to the output stream
			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = plaintextInputStream.read(buffer)) != -1) {
				cipherOutputStream.write(buffer, 0, bytesRead);
			}

			// Close the streams
			cipherOutputStream.close();
			plaintextInputStream.close();

			// Get the encrypted data as bytes
			byte[] encryptedData = encryptedOutputStream.toByteArray();

			// Set response headers for file download
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
			headers.setContentDispositionFormData("attachment", "encrypted_data.csv");

			return new ResponseEntity<>(encryptedData, headers, HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
		}
	}

	@PostMapping("/decrypt")
	public ResponseEntity<byte[]> decryptCSVFile(@RequestParam("encryptedFile") MultipartFile encryptedFile,
												 @RequestParam("decryptionKey") String decryptionKey) {
		if (encryptedFile.isEmpty()) {
			return ResponseEntity.badRequest().body(null);
		}

		try (InputStream encryptedInputStream = encryptedFile.getInputStream();
			 ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream()) {

			// Generate SecretKey from provided key
			SecretKey secretKey = generateSecretKey(decryptionKey);

			// Create the cipher and initialize it for decryption
			Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, secretKey);

			// Create a CipherInputStream to decrypt the data
			CipherInputStream cipherInputStream = new CipherInputStream(encryptedInputStream, cipher);

			// Read encrypted data from the input stream and write decrypted data to the output stream
			byte[] buffer = new byte[4096];
			int bytesRead;
			while ((bytesRead = cipherInputStream.read(buffer)) != -1) {
				decryptedOutputStream.write(buffer, 0, bytesRead);
			}

			// Close the streams
			cipherInputStream.close();
			encryptedInputStream.close();

			// Get the decrypted data as bytes
			byte[] decryptedData = decryptedOutputStream.toByteArray();

			// Set response headers for file download
			HttpHeaders headers = new HttpHeaders();
			headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
			headers.setContentDispositionFormData("attachment", "decrypted_data.csv");

			return new ResponseEntity<>(decryptedData, headers, HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
		}
	}

	private SecretKey generateSecretKey(String key) throws Exception {
		DESKeySpec keySpec = new DESKeySpec(key.getBytes());
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ENCRYPTION_ALGORITHM);
		return keyFactory.generateSecret(keySpec);
	}
}
