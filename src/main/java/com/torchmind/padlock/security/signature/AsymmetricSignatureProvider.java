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
package com.torchmind.padlock.security.signature;

import com.torchmind.padlock.security.AbstractDelegatingProvider;
import com.torchmind.padlock.security.IProvider;

import javax.annotation.Nonnull;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

/**
 * Provides a {@link com.torchmind.padlock.security.signature.ISignatureProvider} implementation utilizing asymmetric
 * cryptography.
 * @author Johannes Donath
 */
public class AsymmetricSignatureProvider extends AbstractDelegatingProvider<Signature, PrivateKey> implements ISignatureProvider<PrivateKey> {

        public AsymmetricSignatureProvider (@Nonnull Signature provider, @Nonnull PrivateKey key) throws IllegalArgumentException {
                super (provider, key);
        }

        /**
         * {@inheritDoc}
         */
        @Nonnull
        @Override
        public IProvider<PrivateKey> key (@Nonnull PrivateKey key) throws IllegalArgumentException {
                try {
                        this.provider ().initSign (key);
                        return super.key (key);
                } catch (InvalidKeyException ex) {
                        throw new IllegalArgumentException ("Invalid private key: " + ex.getMessage ());
                }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public ByteBuffer sign (@Nonnull ByteBuffer metadata) throws SignatureException {
                this.provider ().update (metadata);
                metadata.rewind ();

                return ByteBuffer.wrap (this.provider ().sign ());
        }
}
