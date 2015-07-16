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
package com.torchmind.padlock.test.metadata;

import com.torchmind.padlock.metadata.AuthenticationClaimMetadata;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import java.time.Instant;
import java.util.UUID;

/**
 * Provides test cases for {@link com.torchmind.padlock.metadata.AuthenticationClaimMetadata}.
 * @author Johannes Donath
 */
@RunWith (MockitoJUnitRunner.class)
public class AuthenticationClaimMetadataTest {

        /**
         * Tests {@link com.torchmind.padlock.metadata.AuthenticationClaimMetadata#expired(java.time.Instant)}.
         */
        @Test
        public void testExpired () {
                AuthenticationClaimMetadata metadata1 = new AuthenticationClaimMetadata (UUID.randomUUID (), Instant.ofEpochSecond (1), Instant.ofEpochSecond (2));
                AuthenticationClaimMetadata metadata2 = new AuthenticationClaimMetadata (UUID.randomUUID (), Instant.now ().minusSeconds (10), Instant.now ().plusSeconds (3600));
                AuthenticationClaimMetadata metadata3 = new AuthenticationClaimMetadata (UUID.randomUUID (), Instant.now ().plusSeconds (3600), Instant.now ().plusSeconds (7200));

                Assert.assertTrue (metadata1.expired ());
                Assert.assertFalse (metadata2.expired ());
                Assert.assertFalse (metadata3.expired ());
        }

        /**
         * Tests {@link com.torchmind.padlock.metadata.AuthenticationClaimMetadata#notYetValid(java.time.Instant)}.
         */
        @Test
        public void testNotYetValid () {
                AuthenticationClaimMetadata metadata1 = new AuthenticationClaimMetadata (UUID.randomUUID (), Instant.ofEpochSecond (1), Instant.ofEpochSecond (2));
                AuthenticationClaimMetadata metadata2 = new AuthenticationClaimMetadata (UUID.randomUUID (), Instant.now ().minusSeconds (10), Instant.now ().plusSeconds (3600));
                AuthenticationClaimMetadata metadata3 = new AuthenticationClaimMetadata (UUID.randomUUID (), Instant.now ().plusSeconds (3600), Instant.now ().plusSeconds (7200));

                Assert.assertFalse (metadata1.notYetValid ());
                Assert.assertFalse (metadata2.notYetValid ());
                Assert.assertTrue (metadata3.notYetValid ());
        }

        /**
         * Tests {@link com.torchmind.padlock.metadata.AuthenticationClaimMetadata#valid(java.time.Instant)}.
         */
        @Test
        public void testValid () {
                AuthenticationClaimMetadata metadata1 = new AuthenticationClaimMetadata (UUID.randomUUID (), Instant.ofEpochSecond (1), Instant.ofEpochSecond (2));
                AuthenticationClaimMetadata metadata2 = new AuthenticationClaimMetadata (UUID.randomUUID (), Instant.now ().minusSeconds (10), Instant.now ().plusSeconds (3600));
                AuthenticationClaimMetadata metadata3 = new AuthenticationClaimMetadata (UUID.randomUUID (), Instant.now ().plusSeconds (3600), Instant.now ().plusSeconds (7200));

                Assert.assertFalse (metadata1.valid ());
                Assert.assertTrue (metadata2.valid ());
                Assert.assertFalse (metadata3.valid ());
        }
}
