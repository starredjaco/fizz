/*
 *  Copyright (c) 2026-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#include <numeric>
#include <vector>

#include <folly/Benchmark.h>
#include <folly/init/Init.h>

#include <fizz/crypto/aead/CryptoUtil.h>

using namespace fizz;

namespace {

// Every AEAD encrypt and decrypt derives a fresh nonce from the record
// sequence number and the connection's static traffic IV key, so createIV runs
// once per TLS record in each direction.
//
// The key is built once rather than per call, so there is no setup to exclude
// and no BenchmarkSuspender is needed.
//
// In production ivLength is a member of the Aead subclass reached through a
// virtual call, so the compiler cannot constant fold it. makeUnpredictable
// reproduces that here; without it this would measure fully unrolled code that
// no caller actually gets.
template <size_t kMaxIVLength, size_t kIVLength>
void createIVBench(uint32_t iters) {
  static const std::vector<uint8_t> key = [] {
    std::vector<uint8_t> k(kIVLength);
    std::iota(k.begin(), k.end(), uint8_t{0});
    return k;
  }();
  const folly::ByteRange trafficIvKey(key.data(), key.size());
  uint64_t seqNum = 0;
  size_t ivLength = kIVLength;

  while (iters--) {
    folly::makeUnpredictable(seqNum);
    folly::makeUnpredictable(ivLength);
    auto iv = createIV<kMaxIVLength>(seqNum, ivLength, trafficIvKey);
    folly::doNotOptimizeAway(iv);
  }
}

} // namespace

// AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 all use a 12 byte IV and go
// through OpenSSLEVPCipher, whose kMaxIVLength is 20. This covers essentially
// all production TLS traffic.
BENCHMARK(createIV_ivLength12_maxIVLength20, iters) {
  createIVBench<20, 12>(iters);
}

// AEGIS-128L uses a 16 byte IV and AEGIS-256 a 32 byte IV, both through
// AEGISCipher, whose kMaxIVLength is 32.
BENCHMARK(createIV_ivLength16_maxIVLength32, iters) {
  createIVBench<32, 16>(iters);
}

BENCHMARK(createIV_ivLength32_maxIVLength32, iters) {
  createIVBench<32, 32>(iters);
}

// fizz is open source, so this uses folly::Init rather than
// initFacebookLight().
int main(int argc, char** argv) {
  const folly::Init init(&argc, &argv);
  folly::runBenchmarks();
  return 0;
}
