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
package com.torchmind.padlock.security.universal;

import javax.annotation.Nonnull;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * Provides a factory for {@link com.torchmind.padlock.security.universal.SymmetricUniversalProvider} instances.
 * @author Johannes Donath
 */
public class SymmetricUniversalProviderFactory implements IUniversalProviderFactory {
        private final String algorithm;
        private final SecretKey secretKey;

        public SymmetricUniversalProviderFactory (@Nonnull String algorithm, @Nonnull SecretKey secretKey) {
                this.algorithm = algorithm;
                this.secretKey = secretKey;
        }

        /**
         * Retrieves the algorithm name.
         * @return The name.
         */
        @Nonnull
        public String algorithm () {
                return this.algorithm;
        }

        /**
         * Retrieves the secret key.
         * @return The secret key.
         */
        @Nonnull
        public SecretKey secretKey () {
                return this.secretKey;
        }

        /**
         * {@inheritDoc}
         */
        @Nonnull
        @Override
        public SymmetricUniversalProvider build () throws IllegalStateException {
                try {
                        return new SymmetricUniversalProvider (Mac.getInstance (this.algorithm ()), this.secretKey ());
                } catch (NoSuchAlgorithmException ex) {
                        throw new IllegalStateException ("Unsupported symmetric signature algorithm: " + ex.getMessage (), ex);
                }
        }
}
