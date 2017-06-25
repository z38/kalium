/**
 * Copyright 2017 Bruno Oliveira, and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.abstractj.kalium.keys;

import org.junit.Test;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_KDF_BLAKE2B_BYTES_MIN;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_KDF_BLAKE2B_BYTES_MAX;
import static org.abstractj.kalium.encoders.Encoder.HEX;
import static org.abstractj.kalium.fixture.TestVectors.KDF_KEY;
import static org.abstractj.kalium.fixture.TestVectors.KDF_CONTEXT;
import static org.abstractj.kalium.fixture.TestVectors.KDF_SUBKEY_9;

import static org.junit.Assert.assertEquals;

public class KeyDerivationTest {
    @Test
    public void testDerive() throws Exception {
        byte[] key = HEX.decode(KDF_KEY);
        KeyDerivation derivation = new KeyDerivation(key, KDF_CONTEXT);
        String result = HEX.encode(derivation.derive(CRYPTO_KDF_BLAKE2B_BYTES_MAX, 9));
        assertEquals("Subkey is invalid", KDF_SUBKEY_9, result);
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidContext() throws Exception {
        byte[] key = HEX.decode(KDF_KEY);
        new KeyDerivation(key, "invalid");
    }

    @Test(expected = RuntimeException.class)
    public void testInvalidKey() throws Exception {
        new KeyDerivation(new byte[1], KDF_CONTEXT);
    }

    @Test(expected = RuntimeException.class)
    public void testDeriveInvalidLength() throws Exception {
        KeyDerivation derivation = new KeyDerivation(HEX.decode(KDF_KEY), KDF_CONTEXT);
        derivation.derive(CRYPTO_KDF_BLAKE2B_BYTES_MIN - 1, 0);
    }
}
