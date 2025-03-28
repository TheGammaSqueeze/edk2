// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

#ifndef BORINGSSL_ECDSA_UTILS_H_
#define BORINGSSL_ECDSA_UTILS_H_


#include "dice/dice.h"

#ifdef __cplusplus
extern "C" {
#endif

#define P384_PRIVATE_KEY_SIZE 48
#define P384_PUBLIC_KEY_SIZE 96
#define P384_SIGNATURE_SIZE 96

// Deterministically generates a public and private key pair from |seed|.
// Since this is deterministic, |seed| is as sensitive as a private key and can
// be used directly as the private key. The |private_key| may use an
// implementation defined format so may only be passed to the |sign| operation.
int P384KeypairFromSeed(uint8_t public_key[P384_PUBLIC_KEY_SIZE],
                        uint8_t private_key[P384_PRIVATE_KEY_SIZE],
                        const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE]);

// Calculates a signature of |message_size| bytes from |message| using
// |private_key|. |private_key| was generated by |keypair_from_seed| to allow
// an implementation to use their own private key format. |signature| points to
// the buffer where the calculated signature is written.
int P384Sign(uint8_t signature[P384_SIGNATURE_SIZE], const uint8_t* message,
             size_t message_size,
             const uint8_t private_key[P384_PRIVATE_KEY_SIZE]);

// Verifies, using |public_key|, that |signature| covers |message_size| bytes
// from |message|.
int P384Verify(const uint8_t* message, size_t message_size,
               const uint8_t signature[P384_SIGNATURE_SIZE],
               const uint8_t public_key[P384_PUBLIC_KEY_SIZE]);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // BORINGSSL_ECDSA_UTILS_H_
