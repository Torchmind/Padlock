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
package com.torchmind.padlock.test;

import com.torchmind.padlock.IAuthenticationClaim;
import com.torchmind.padlock.Padlock;
import com.torchmind.padlock.metadata.AuthenticationClaimMetadata;
import com.torchmind.padlock.metadata.codec.IMetadataCodec;
import com.torchmind.padlock.security.signature.ISignatureProvider;
import com.torchmind.padlock.security.verification.IVerificationProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import java.nio.ByteBuffer;
import java.security.SignatureException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Provides test cases for {@link com.torchmind.padlock.Padlock}.
 * @author Johannes Donath
 */
@RunWith (MockitoJUnitRunner.class)
public class PadlockTest {
        private static final AuthenticationClaimMetadata TEST_METADATA = new AuthenticationClaimMetadata (UUID.fromString ("8ccb03dc-55dd-4ebd-9b68-79ea3b1fc79a"), Instant.ofEpochSecond (1), Instant.ofEpochSecond (2));
        private static final byte[] TEST_METADATA_ENCODED = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        private static final byte[] TEST_SIGNATURE = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        @Mock
        private IMetadataCodec metadataCodec;
        @Mock
        private IAuthenticationClaim<AuthenticationClaimMetadata> claim;
        @Mock
        private ISignatureProvider signatureProvider;
        @Mock
        private IVerificationProvider verificationProvider;

        /**
         * Prepares the test class.
         */
        @Before
        public void setup () throws SignatureException {
                // @formatter:off
                {
                        Mockito.when (this.metadataCodec.encode (AuthenticationClaimMetadata.class, TEST_METADATA))
                                .thenReturn (ByteBuffer.wrap (TEST_METADATA_ENCODED));

                        Mockito.when (this.metadataCodec.decode (AuthenticationClaimMetadata.class, ByteBuffer.wrap (TEST_METADATA_ENCODED)))
                                .thenReturn (TEST_METADATA);
                }

                {
                        Mockito.when (this.claim.metadata ())
                               .thenReturn (TEST_METADATA);

                        Mockito.when (this.claim.metadataType ())
                                .thenReturn (AuthenticationClaimMetadata.class);

                        Mockito.when (this.claim.signature ())
                                .thenReturn (ByteBuffer.wrap (TEST_SIGNATURE));
                }

                {
                        Mockito.when (this.signatureProvider.sign (ByteBuffer.wrap (TEST_METADATA_ENCODED)))
                                .thenReturn (ByteBuffer.wrap (TEST_SIGNATURE));
                }

                {
                        Mockito.when (this.verificationProvider.verify (ByteBuffer.wrap (TEST_METADATA_ENCODED), ByteBuffer.wrap (TEST_SIGNATURE)))
                                .thenReturn (true);
                }
                // @formatter:off
        }

        /**
         * Tests {@link com.torchmind.padlock.Padlock#encode(com.torchmind.padlock.IAuthenticationClaim)}.
         */
        @Test
        public void testEncode () {
                Padlock padlock = Padlock.builder ().metadataCodec (this.metadataCodec).build ();
                String encoded = padlock.encode (this.claim);

                // @formatter:off
                {
                        Mockito.verify (this.metadataCodec)
                                .encode (AuthenticationClaimMetadata.class, TEST_METADATA);
                }

                {
                        Mockito.verify (this.claim)
                                .metadataType ();

                        Mockito.verify (this.claim)
                                .metadata ();

                        Mockito.verify (this.claim)
                                .signature ();
                }
                // @formatter:on

                Assert.assertEquals ("AQIDBA==.AQIDBA==", encoded);
        }

        /**
         * Tests {@link com.torchmind.padlock.Padlock#decode(Class, String)}.
         */
        @Test
        public void testDecode () {
                Padlock padlock = Padlock.builder ().metadataCodec (this.metadataCodec).build ();
                IAuthenticationClaim<AuthenticationClaimMetadata> claim = padlock.decode (AuthenticationClaimMetadata.class, "AQIDBA==.AQIDBA==");

                // @formatter:on
                {
                        Mockito.verify (this.metadataCodec)
                               .decode (AuthenticationClaimMetadata.class, ByteBuffer.wrap (TEST_METADATA_ENCODED));
                }
                // @formatter:off

                Assert.assertEquals (AuthenticationClaimMetadata.class, claim.metadataType ());
                Assert.assertEquals (TEST_METADATA, claim.metadata ());
                Assert.assertEquals (ByteBuffer.wrap (TEST_SIGNATURE), claim.signature ());
        }

        /**
         * Tests {@link com.torchmind.padlock.Padlock#sign(Class, com.torchmind.padlock.metadata.AuthenticationClaimMetadata)}.
         */
        @Test
        public void testSign () throws SignatureException {
                Padlock padlock = Padlock.builder ().metadataCodec (this.metadataCodec).signatureProvider (this.signatureProvider).build ();
                IAuthenticationClaim<AuthenticationClaimMetadata> claim = padlock.sign (AuthenticationClaimMetadata.class, TEST_METADATA);

                // @formatter:off
                {
                        Mockito.verify (this.metadataCodec)
                                .encode (AuthenticationClaimMetadata.class, TEST_METADATA);
                }

                {
                        Mockito.verify (this.signatureProvider)
                                .sign (ByteBuffer.wrap (TEST_METADATA_ENCODED));
                }
                // @formatter:on

                Assert.assertEquals (AuthenticationClaimMetadata.class, claim.metadataType ());
                Assert.assertEquals (TEST_METADATA, claim.metadata ());
                Assert.assertEquals (ByteBuffer.wrap (TEST_SIGNATURE), claim.signature ());
        }

        /**
         * Tests {@link com.torchmind.padlock.Padlock#sign(Class, com.torchmind.padlock.metadata.AuthenticationClaimMetadata)}
         * sanity checks.
         */
        @Test (expected = IllegalArgumentException.class)
        public void testSignLimitation () throws SignatureException {
                Padlock padlock = Padlock.builder ().metadataCodec (this.metadataCodec).signatureProvider (this.signatureProvider).maximumValidityDuration (Duration.ZERO).build ();
                IAuthenticationClaim<AuthenticationClaimMetadata> claim = padlock.sign (AuthenticationClaimMetadata.class, TEST_METADATA);
        }

        /**
         * Tests {@link com.torchmind.padlock.Padlock#verify(com.torchmind.padlock.IAuthenticationClaim)}.
         */
        @Test
        public void testVerify () {
                Padlock padlock = Padlock.builder ().metadataCodec (this.metadataCodec).verificationProvider (this.verificationProvider).build ();
                Assert.assertTrue (padlock.verify (this.claim));

                // @formatter:off
                {
                        Mockito.verify (this.metadataCodec)
                                .encode (AuthenticationClaimMetadata.class, TEST_METADATA);
                }

                {
                        Mockito.verify (this.verificationProvider)
                                .verify (ByteBuffer.wrap (TEST_METADATA_ENCODED), ByteBuffer.wrap (TEST_SIGNATURE));
                }
                // @formatter:on
        }
}
