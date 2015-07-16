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
package com.torchmind.padlock.test.metadata.codec;

import com.torchmind.padlock.metadata.AuthenticationClaimMetadata;
import com.torchmind.padlock.metadata.codec.JacksonMetadataCodec;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.UUID;

/**
 * Provides test cases for {@link com.torchmind.padlock.metadata.codec.JacksonMetadataCodec}.
 * @author Johannes Donath
 */
@RunWith (MockitoJUnitRunner.class)
public class JacksonMetadataCodecTest {
        private static final AuthenticationClaimMetadata METADATA_DECODED = new AuthenticationClaimMetadata (UUID.fromString ("8ccb03dc-55dd-4ebd-9b68-79ea3b1fc79a"), Instant.ofEpochSecond (1), Instant.ofEpochSecond (2));
        private static final byte[] METADATA_ENCODED = new byte[] { 123, 34, 105, 100, 101, 110, 116, 105, 102, 105, 101, 114, 34, 58, 34, 56, 99, 99, 98, 48, 51, 100, 99, 45, 53, 53, 100, 100, 45, 52, 101, 98, 100, 45, 57, 98, 54, 56, 45, 55, 57, 101, 97, 51, 98, 49, 102, 99, 55, 57, 97, 34, 44, 34, 105, 115, 115, 117, 97, 110, 99, 101, 34, 58, 49, 46, 48, 48, 48, 48, 48, 48, 48, 48, 48, 44, 34, 101, 120, 112, 105, 114, 97, 116, 105, 111, 110, 34, 58, 50, 46, 48, 48, 48, 48, 48, 48, 48, 48, 48, 125 };

        private JacksonMetadataCodec codec;

        /**
         * Prepares the environment for test cases contained herein.
         */
        @Before
        public void prepare () {
                this.codec = new JacksonMetadataCodec ();
        }

        /**
         * Tests {@link com.torchmind.padlock.metadata.codec.JacksonMetadataCodec#encode(Class, com.torchmind.padlock.metadata.AuthenticationClaimMetadata)}.
         */
        @Test
        public void testEncode () {
                ByteBuffer encoded = this.codec.encode (AuthenticationClaimMetadata.class, METADATA_DECODED);
                Assert.assertArrayEquals (METADATA_ENCODED, encoded.array ());
        }

        /**
         * Tests {@link com.torchmind.padlock.metadata.codec.JacksonMetadataCodec#decode(Class, java.nio.ByteBuffer)}.
         */
        @Test
        public void testDecode () {
                AuthenticationClaimMetadata decoded = this.codec.decode (AuthenticationClaimMetadata.class, ByteBuffer.wrap (METADATA_ENCODED));
                Assert.assertEquals (METADATA_DECODED, decoded);
        }
}
