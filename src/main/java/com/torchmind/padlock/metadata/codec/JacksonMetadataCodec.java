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
package com.torchmind.padlock.metadata.codec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.torchmind.padlock.metadata.AuthenticationClaimMetadata;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Provides a metadata codec implementation utilizing Jackson's {@link com.fasterxml.jackson.databind.ObjectMapper}.
 * @author Johannes Donath
 */
@ThreadSafe
public class JacksonMetadataCodec implements IMetadataCodec {
        private final ObjectReader reader;
        private final ObjectWriter writer;

        public JacksonMetadataCodec () {
                ObjectMapper mapper = this.createMapper ();

                this.reader = mapper.reader ();
                this.writer = mapper.writer ();
        }

        /**
         * Retrieves a new mapper.
         * @return The mapper.
         */
        @Nonnull
        protected ObjectMapper createMapper () {
                ObjectMapper mapper = new ObjectMapper ();
                mapper.findAndRegisterModules ();
                return mapper;
        }

        /**
         * Retrieves the object reader.
         * @return The reader.
         */
        public ObjectReader reader () {
                return this.reader;
        }

        /**
         * Retrieves the object writer.
         * @return The writer.
         */
        public ObjectWriter writer () {
                return this.writer;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public <M extends AuthenticationClaimMetadata> M decode (@Nonnull Class<M> type, @Nonnull ByteBuffer encoded) throws IllegalArgumentException {
                try {
                        byte[] encodedBytes = new byte[encoded.remaining ()];
                        encoded.get (encodedBytes);

                        return this.reader ().withType (type).readValue (encodedBytes);
                } catch (IOException ex) {
                        throw new IllegalArgumentException ("Could not decode claim metadata: " + ex.getMessage (), ex);
                }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public <M extends AuthenticationClaimMetadata> ByteBuffer encode (@Nonnull Class<M> type, @Nonnull M decoded) throws IllegalStateException {
                try {
                        return ByteBuffer.wrap (this.writer ().writeValueAsBytes (decoded));
                } catch (IOException ex) {
                        throw new IllegalStateException ("Could not encode claim metadata: " + ex.getMessage (), ex);
                }
        }
}
