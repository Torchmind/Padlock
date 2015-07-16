/*
 * Copyright 2015 Johannes Donath <johannesd@torchmind.com>
 * and other copyright owners as documented in the project's IP log.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.torchmind.padlock.test.security.signature;

import com.torchmind.padlock.security.signature.AsymmetricSignatureProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Provides test cases for {@link com.torchmind.padlock.security.signature.AsymmetricSignatureProvider}.
 * @author Johannes Donath
 */
@RunWith (MockitoJUnitRunner.class)
public class AsymmetricSignatureProviderTest {
        public static final byte[] TEST_BYTES = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        public static final byte[] TEST_BYTES_SIGNED = new byte[] { 9, -67, -6, -85, -100, -125, -88, -87, -38, 121, 103, 35, -103, -12, 45, 124, -23, 103, 17, 122, -59, 114, 5, -111, 13, 64, 56, 15, 117, 6, 14, 19, -100, -55, 88, -81, 116, 127, -113, -21, 72, 26, 65, 29, 36, 85, 127, -89, -112, 84, 13, -47, 88, -107, 67, -52, -6, 37, 96, -118, 92, 70, 122, 85 };
        public static final byte[] KEY_BYTES = new byte[] { 48, -126, 1, 84, 2, 1, 0, 48, 13, 6, 9, 42, -122, 72, -122, -9, 13, 1, 1, 1, 5, 0, 4, -126, 1, 62, 48, -126, 1, 58, 2, 1, 0, 2, 65, 0, -119, 39, -112, 104, -47, -28, -19, -55, 9, 0, -42, -28, 96, 43, -14, -102, 74, -12, 30, 118, 91, -17, 12, 42, 45, -116, 115, -40, 42, 59, 10, 64, 95, 106, -78, -100, -15, -98, -17, -10, 78, 118, -114, -51, 91, -88, -58, -37, 33, -57, 64, -111, 55, 89, 119, 77, 21, 110, 90, -17, -124, 46, -100, 123, 2, 3, 1, 0, 1, 2, 64, 107, -85, 91, 122, 110, 11, -63, 127, -88, 73, -72, 104, -33, -10, -96, 36, -17, -30, 100, 103, -106, 20, 59, 0, -127, 113, 89, 31, -63, 71, 71, -21, -55, -28, -3, -103, 114, 2, -108, 63, -27, -26, -66, -76, -65, 17, 51, 7, -93, 47, -4, 44, -26, 75, -108, 115, 54, 38, 48, 19, -86, -113, -127, 65, 2, 33, 0, -54, -122, -21, 88, 26, -18, 45, -37, 82, 32, -50, 53, -78, 115, -118, -39, -81, -108, -22, -96, 125, -122, -78, -44, 88, -49, -48, -21, 73, -55, -40, 47, 2, 33, 0, -83, 94, 7, 93, -62, -121, 43, 26, -68, 115, -127, 82, 73, -62, -78, -35, -96, -28, 111, -85, -40, -34, -38, -19, -53, -6, 87, -29, -38, 11, 97, 117, 2, 32, 77, -61, 120, 98, 32, 21, 12, 46, -122, 94, 106, 79, 91, -15, -39, -126, -76, 84, 109, -78, -86, 0, 42, 114, 54, -105, -75, 20, 99, 4, -55, -87, 2, 33, 0, -92, -89, 80, 49, -79, 70, 53, 31, 16, 106, 87, 33, 115, 34, 114, 68, 97, -63, 115, 121, -17, -32, 64, 103, 102, -70, 29, -19, 46, 50, 110, -35, 2, 32, 82, -120, 120, 116, -95, -11, -127, -82, 123, -94, 121, 97, -114, 111, -68, -82, -7, 62, -40, -19, -46, -89, -55, 113, 121, 99, -68, 11, -112, 75, -43, -23 };

        private PrivateKey rsaKey;

        /**
         * Prepares the class for test cases contained herein.
         */
        @Before
        public void setupStatic () throws NoSuchAlgorithmException, InvalidKeySpecException {
                KeyFactory factory = KeyFactory.getInstance ("RSA");
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec (KEY_BYTES);
                rsaKey = factory.generatePrivate (keySpec);
        }

        /**
         * Tests {@link com.torchmind.padlock.security.signature.AsymmetricSignatureProvider#sign(java.nio.ByteBuffer)}.
         */
        @Test
        public void testSign () throws NoSuchAlgorithmException, SignatureException {
                AsymmetricSignatureProvider provider = new AsymmetricSignatureProvider (Signature.getInstance ("SHA1withRSA"), this.rsaKey);
                ByteBuffer signed = provider.sign (ByteBuffer.wrap (TEST_BYTES));

                Assert.assertArrayEquals (TEST_BYTES_SIGNED, signed.array ());
        }
}
