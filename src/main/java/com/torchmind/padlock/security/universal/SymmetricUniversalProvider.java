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

import com.torchmind.padlock.security.AbstractDelegatingProvider;
import com.torchmind.padlock.security.IProvider;

import javax.annotation.Nonnull;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * Provides a universal, symmetric implementation of {@link com.torchmind.padlock.security.signature.ISignatureProvider}
 * and {@link com.torchmind.padlock.security.verification.IVerificationProvider}.
 * @author Johannes Donath
 */
public class SymmetricUniversalProvider extends AbstractDelegatingProvider<Mac, SecretKey> implements IUniversalProvider<SecretKey> {

        public SymmetricUniversalProvider (@Nonnull Mac provider, @Nonnull SecretKey key) throws IllegalArgumentException {
                super (provider, key);
        }

        /**
         * {@inheritDoc}
         */
        @Nonnull
        @Override
        public IProvider<SecretKey> key (@Nonnull SecretKey key) throws IllegalArgumentException {
                try {
                        this.provider ().init (key);
                        return super.key (key);
                } catch (InvalidKeyException ex) {
                        throw new IllegalArgumentException ("Invalid secret key: " + ex.getMessage (), ex);
                }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public ByteBuffer sign (@Nonnull ByteBuffer metadata) throws SignatureException {
                this.provider ().update (metadata);
                return ByteBuffer.wrap (this.provider ().doFinal ());
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean verify (@Nonnull ByteBuffer metadata, @Nonnull ByteBuffer signature) {
                this.provider ().update (metadata);

                byte[] signatureBytes = new byte[signature.remaining ()];
                signature.get (signatureBytes);

                return Arrays.equals (this.provider ().doFinal (), signatureBytes);
        }
}
