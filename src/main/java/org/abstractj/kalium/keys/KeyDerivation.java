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

import static org.abstractj.kalium.NaCl.sodium;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_KDF_BLAKE2B_BYTES_MIN;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_KDF_BLAKE2B_BYTES_MAX;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_KDF_BLAKE2B_CONTEXTBYTES;
import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_KDF_BLAKE2B_KEYBYTES;
import static org.abstractj.kalium.crypto.Util.checkLength;
import static org.abstractj.kalium.crypto.Util.isValid;

public class KeyDerivation {

    private final byte[] masterKey;
    private final byte[] context;

    public KeyDerivation(byte[] secretKey, String context) {
        this(secretKey, context.getBytes());
    }

    public KeyDerivation(byte[] masterKey, byte[] context) {
        checkLength(masterKey, CRYPTO_KDF_BLAKE2B_KEYBYTES);
        checkLength(context, CRYPTO_KDF_BLAKE2B_CONTEXTBYTES);
        this.masterKey = masterKey;
        this.context = context;
    }

    public byte[] derive(int length, int id) {
        if (length < CRYPTO_KDF_BLAKE2B_BYTES_MIN || length > CRYPTO_KDF_BLAKE2B_BYTES_MAX) {
            throw new RuntimeException("Invalid length");
        }
        byte[] subkey = new byte[length];
        isValid(sodium().crypto_kdf_blake2b_derive_from_key(subkey, subkey.length, id, context, masterKey),
                "Key derivation failed");
        return subkey;
    }
}
