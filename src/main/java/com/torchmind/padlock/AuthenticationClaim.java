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
package com.torchmind.padlock;

import com.torchmind.padlock.metadata.AuthenticationClaimMetadata;

import javax.annotation.Nonnull;
import java.nio.ByteBuffer;

/**
 * Provides an implementation of {@link com.torchmind.padlock.IAuthenticationClaim} for internal use.
 * @author Johannes Donath
 */
class AuthenticationClaim<M extends AuthenticationClaimMetadata> implements IAuthenticationClaim<M> {
        private final M metadata;
        private final Class<M> metadataType;
        private final ByteBuffer signature;

        public AuthenticationClaim (@Nonnull Class<M> metadataType, @Nonnull M metadata, @Nonnull ByteBuffer signature) {
                this.metadataType = metadataType;
                this.metadata = metadata;
                this.signature = signature;
        }

        public AuthenticationClaim (@Nonnull AuthenticationClaim<M> claim) {
                this (claim.metadataType (), claim.metadata (), claim.signature ());
        }

        /**
         * {@inheritDoc}
         */
        @Nonnull
        @Override
        public M metadata () {
                return this.metadata;
        }

        /**
         * {@inheritDoc}
         */
        @Nonnull
        @Override
        public Class<M> metadataType () {
                return this.metadataType;
        }

        /**
         * {@inheritDoc}
         */
        @Nonnull
        @Override
        public ByteBuffer signature () {
                return this.signature;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean equals (Object o) {
                if (this == o) { return true; }
                if (!(o instanceof AuthenticationClaim)) { return false; }

                AuthenticationClaim<?> that = (AuthenticationClaim<?>) o;

                if (!metadata.equals (that.metadata)) { return false; }
                if (!metadataType.equals (that.metadataType)) { return false; }
                return signature.equals (that.signature);

        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int hashCode () {
                int result = metadata.hashCode ();
                result = 31 * result + metadataType.hashCode ();
                result = 31 * result + signature.hashCode ();
                return result;
        }
}
