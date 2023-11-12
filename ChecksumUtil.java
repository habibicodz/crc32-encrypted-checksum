package com.deepforensic.gallerylock.business.encryption;

import com.deepforensic.gallerylock.Model.EncryptedHeader;
import com.deepforensic.gallerylock.business.properties.Aes;
import com.deepforensic.gallerylock.business.repositories.Key;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.security.spec.AlgorithmParameterSpec;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ChecksumUtil {

    /*
    * Fastest method to calculate checksum of an encrypted file
    * This method uses CRC32 hashing algorithm to obtain checksum from an encrypted file
    * CRC32 is for use of small number of files only <100k
    * and using Java NIO Buffer, FileChannel, Cipher.update(Buffer, Buffer) to achieve faster speed and less memory usage
    * */

    public static String calculateCRC32Checksum (final SecretKey secretKey, final File file) {
        String checksum = null;
        CRC32 messageDigest = new CRC32();

        //Using try-with resources to open streams
        try (FileInputStream fileInputStream = new FileInputStream(file);
             FileChannel readableByteChannel = fileInputStream.getChannel()) {

            //Deserializing encrypted header to obtain IV
            ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
            EncryptedHeader header = (EncryptedHeader) objectInputStream.readObject();
            byte[] iv = header.getIv();

            //Iv Parameter spec to pass IV to Cipher Object
            AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance(Aes.ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec);

            //Max buffer to read
            int maxBuffer = Key.DEFAULT_BUFFER;

            //Check if the file is less than a minimum buffer length to avoid EOL exception
            int bufferLength = (int) Math.min(maxBuffer, file.length());

            //Cipher Buffer to read
            ByteBuffer cipherBuffer = ByteBuffer.allocate(bufferLength);

            //Decipher buffer (using cipher.getOutputSize(bufferLength) to get exact buffer length after the cipher processing.
            ByteBuffer plainBuffer = ByteBuffer.allocate(cipher.getOutputSize(bufferLength));

            //Reading a buffer (Pointer moved to the end)
            int readLength = readableByteChannel.read(cipherBuffer);

            //Flipping a buffer
            //Flipping a buffer must be done after any operation done to buffer object
            //Because writing or reading from buffer make the pointer moved to the end of the buffer.
            //calling flip move the pointer to the start again
            cipherBuffer.flip();

            //Checking if the file reached to the end
            while (readLength != -1) {
                //Decrypting cipher buffer and storing to plain buffer
                cipher.update(cipherBuffer, plainBuffer);

                //Moving pointer of Plain and Cipher buffer to start
                plainBuffer.flip();
                cipherBuffer.flip();

                //Hashing the plain buffer
                messageDigest.update(plainBuffer);

                //Flipping plain buffer
                plainBuffer.flip();

                //Reading the file in loop
                readLength = readableByteChannel.read(cipherBuffer);

                //Flipping the buffer again
                cipherBuffer.flip();
            }

            //Finishing the deciphering by calling doFinal() on the cipher object
            cipher.doFinal();

            //Obtaining string value from checksum bytes
            checksum = String.valueOf(messageDigest.getValue());

        }catch (Exception ignored){
            //Ignore the exception
        }

        //Resetting the CRC32 digest to initial state
        messageDigest.reset();

        //Returning the checksum value
        return checksum;
    }
}
