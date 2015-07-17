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
package com.torchmind.padlock.test.security.universal;

import com.torchmind.padlock.security.universal.SymmetricUniversalProvider;
import com.torchmind.padlock.security.universal.SymmetricUniversalProviderFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * Provides test cases for {@link com.torchmind.padlock.security.universal.SymmetricUniversalProviderFactory}.
 * @author Johannes Donath
 */
@RunWith (MockitoJUnitRunner.class)
public class SymmetricUniversalProviderFactoryTest {
        public static final byte[] KEY_BYTES = new byte[] { 56, -124, -95, 53, 80, -6, 92, 70, -49, -111, -22, -95, -23, 27, -4, -58, -99, 96, -85, -6, 76, 42, 33, -11, -69, 77, 106, 4, -35, 82, 12, -22, 57, 82, 124, 127, -3, 47, 9, -111, 82, 54, 11, 125, -89, -83, 1, 22, -112, -37, 88, -84, -118, 77, 40, 30, -50, 106, 70, -11, -67, -23, 10, 33 };

        private SecretKey secretKey;

        /**
         * Prepares the environment for test cases contained herein.
         */
        @Before
        public void setup () throws NoSuchAlgorithmException {
                this.secretKey = new SecretKeySpec (KEY_BYTES, "HmacSHA1");
        }

        /**
         * Tests {@link com.torchmind.padlock.security.universal.SymmetricUniversalProviderFactory#build()}.
         */
        @Test
        public void testBuild () {
                SymmetricUniversalProviderFactory factory = new SymmetricUniversalProviderFactory ("HmacSHA1", this.secretKey);

                SymmetricUniversalProvider provider1 = factory.build ();
                SymmetricUniversalProvider provider2 = factory.build ();

                Assert.assertNotNull (provider1);
                Assert.assertNotNull (provider2);
                Assert.assertNotEquals (provider1, provider2);
        }
}
