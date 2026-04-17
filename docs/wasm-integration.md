# WASM Integration Guide

## Overview

pqctoday-tpm compiles to WebAssembly via Emscripten, enabling a full TPM 2.0
V1.85 PQC emulator to run in the browser. This powers the PQC Today app's
TPM workshop tools without any server-side dependencies.

## Architecture

```
PQC Today React App
  │
  ▼
pqctpm.ts (TypeScript API)
  │
  ▼
pqctpm.js (Emscripten glue)
  │
  ▼
pqctpm.wasm (libtpms compiled)
  │
  ▼
libcrypto.a (OpenSSL 3.6+ WASM, linked statically)
```

## Build

### Prerequisites

- Emscripten SDK (emsdk) — same version as softhsmv3 WASM builds
- OpenSSL 3.6.2 WASM build — reuse from `~/antigravity/softhsmv3/build-wasm/`
- CMake 3.16+

### Build Steps

```bash
# 1. Activate emsdk
source ~/emsdk/emsdk_env.sh

# 2. Build (from repo root)
cd wasm
mkdir build && cd build
emcmake cmake .. \
  -DOPENSSL_WASM_DIR=~/antigravity/softhsmv3/build-wasm/openssl \
  -DCMAKE_BUILD_TYPE=Release
emmake make -j$(nproc)

# Output: pqctpm.js + pqctpm.wasm
```

### Build Configuration

```cmake
# wasm/CMakeLists.txt

cmake_minimum_required(VERSION 3.16)
project(pqctpm C)

# Emscripten flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} \
  -s WASM=1 \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s INITIAL_MEMORY=33554432 \
  -s MAXIMUM_MEMORY=268435456 \
  -s MODULARIZE=1 \
  -s EXPORT_NAME='PqcTpmModule' \
  -s EXPORTED_FUNCTIONS='[\"_TPMLIB_Process\",\"_TPMLIB_Startup\",\"_TPMLIB_Shutdown\",\"_malloc\",\"_free\"]' \
  -s EXPORTED_RUNTIME_METHODS='[\"ccall\",\"cwrap\",\"HEAPU8\"]' \
  -s NO_EXIT_RUNTIME=1 \
  -s FILESYSTEM=0 \
  -O2")

# libtpms source files (subset needed for WASM)
# Exclude: POSIX file I/O, socket code, swtpm wrapper
file(GLOB_RECURSE LIBTPMS_SOURCES
  ${CMAKE_SOURCE_DIR}/../libtpms/src/tpm2/TPMCmd/tpm/src/*.c
)

# Exclude POSIX-specific files
list(FILTER LIBTPMS_SOURCES EXCLUDE REGEX ".*Platform.*")

# Include paths
include_directories(
  ${CMAKE_SOURCE_DIR}/../libtpms/src/tpm2/TPMCmd/tpm/include
  ${OPENSSL_WASM_DIR}/include
)

# Link OpenSSL WASM
add_executable(pqctpm ${LIBTPMS_SOURCES} wasm_platform.c)
target_link_libraries(pqctpm
  ${OPENSSL_WASM_DIR}/lib/libcrypto.a
)
```

### Platform Stub

libtpms expects a platform layer for NVRAM, entropy, and clock. In WASM,
we stub these with in-memory implementations:

```c
// wasm/wasm_platform.c

#include <string.h>
#include <stdlib.h>

// In-memory NVRAM (no file system in WASM)
static unsigned char nvram[65536];
static size_t nvram_size = 0;

// NVRAM read/write stubs
int _plat__NvMemoryRead(unsigned int startOffset, unsigned int size, void *data) {
    if (startOffset + size > sizeof(nvram)) return -1;
    memcpy(data, nvram + startOffset, size);
    return 0;
}

int _plat__NvMemoryWrite(unsigned int startOffset, unsigned int size, const void *data) {
    if (startOffset + size > sizeof(nvram)) return -1;
    memcpy(nvram + startOffset, data, size);
    if (startOffset + size > nvram_size) nvram_size = startOffset + size;
    return 0;
}

// Entropy from crypto.getRandomValues() via Emscripten
int _plat__GetEntropy(unsigned char *output, uint32_t size) {
    // Emscripten provides /dev/urandom emulation backed by crypto.getRandomValues()
    // This is automatically available when FILESYSTEM=0 is not set,
    // or we can use EM_ASM to call crypto.getRandomValues directly
    return RAND_bytes(output, size);  // OpenSSL's RAND already uses Emscripten entropy
}

// Clock (millisecond timer)
uint64_t _plat__ClockGetTime(void) {
    return (uint64_t)(emscripten_get_now() * 1000.0);
}
```

## TypeScript API

```typescript
// wasm/pqctpm.ts

interface PqcTpmModule {
  ccall: (fn: string, ret: string, argTypes: string[], args: any[]) => any
  cwrap: (fn: string, ret: string, argTypes: string[]) => Function
  HEAPU8: Uint8Array
  _malloc: (size: number) => number
  _free: (ptr: number) => void
}

export class PqcTpm {
  private module: PqcTpmModule
  private process: (cmdPtr: number, cmdLen: number, rspPtr: number, rspLenPtr: number) => number

  static async init(): Promise<PqcTpm> {
    const factory = await import('./pqctpm.js')
    const module = await factory.default()
    return new PqcTpm(module)
  }

  private constructor(module: PqcTpmModule) {
    this.module = module
    this.process = module.cwrap('TPMLIB_Process', 'number',
      ['number', 'number', 'number', 'number']) as any
  }

  startup(): void {
    // Send TPM2_Startup(SU_CLEAR) command
    const cmd = this.buildCommand(0x00000144, new Uint8Array([0x00, 0x00])) // SU_CLEAR
    this.sendCommand(cmd)
  }

  shutdown(): void {
    // Send TPM2_Shutdown(SU_CLEAR) command
    const cmd = this.buildCommand(0x00000145, new Uint8Array([0x00, 0x00]))
    this.sendCommand(cmd)
  }

  // --- PQC Operations ---

  createPrimaryMlKem(hierarchy: number, scheme: 'mlkem768' | 'mlkem1024'): {
    handle: number
    publicKey: Uint8Array
  } {
    // Build TPM2_CreatePrimary with ML-KEM template
    // ...
  }

  createMlDsaKey(parentHandle: number, scheme: 'mldsa44' | 'mldsa65' | 'mldsa87'): {
    publicKey: Uint8Array
    privateBlob: Uint8Array
  } {
    // Build TPM2_Create with ML-DSA template
    // ...
  }

  encapsulate(keyHandle: number): {
    ciphertext: Uint8Array
    sharedSecret: Uint8Array
  } {
    // Build TPM2_Encapsulate command
    const cmd = this.buildCommand(0x000001A2, this.marshalHandle(keyHandle))
    const rsp = this.sendCommand(cmd)
    return this.unmarshalEncapsulateResponse(rsp)
  }

  decapsulate(keyHandle: number, ciphertext: Uint8Array): Uint8Array {
    // Build TPM2_Decapsulate command
    const payload = this.concat(this.marshalHandle(keyHandle), this.marshalTPM2B(ciphertext))
    const cmd = this.buildCommand(0x000001A3, payload)
    const rsp = this.sendCommand(cmd)
    return this.unmarshalSharedSecret(rsp)
  }

  sign(keyHandle: number, message: Uint8Array): Uint8Array {
    // Build TPM2_SignDigest command
    const payload = this.concat(this.marshalHandle(keyHandle), this.marshalTPM2B(message))
    const cmd = this.buildCommand(0x000001A8, payload)
    const rsp = this.sendCommand(cmd)
    return this.unmarshalSignature(rsp)
  }

  verify(keyHandle: number, message: Uint8Array, signature: Uint8Array): boolean {
    // Build TPM2_VerifyDigestSignature command
    const payload = this.concat(
      this.marshalHandle(keyHandle),
      this.marshalTPM2B(message),
      this.marshalTPM2B(signature)
    )
    const cmd = this.buildCommand(0x000001A9, payload)
    try {
      this.sendCommand(cmd)
      return true
    } catch {
      return false
    }
  }

  // --- Low-level ---

  private sendCommand(command: Uint8Array): Uint8Array {
    const cmdPtr = this.module._malloc(command.length)
    this.module.HEAPU8.set(command, cmdPtr)

    const rspPtr = this.module._malloc(8192)  // MAX_RESPONSE_SIZE
    const rspLenPtr = this.module._malloc(4)

    const rc = this.process(cmdPtr, command.length, rspPtr, rspLenPtr)

    const rspLen = new DataView(this.module.HEAPU8.buffer).getUint32(rspLenPtr, true)
    const response = new Uint8Array(this.module.HEAPU8.buffer, rspPtr, rspLen).slice()

    this.module._free(cmdPtr)
    this.module._free(rspPtr)
    this.module._free(rspLenPtr)

    if (rc !== 0) throw new Error(`TPM error: 0x${rc.toString(16)}`)
    return response
  }

  private buildCommand(commandCode: number, payload: Uint8Array): Uint8Array {
    // TPM2 command header: tag(2) + size(4) + cc(4) + payload
    const size = 10 + payload.length
    const buf = new ArrayBuffer(size)
    const view = new DataView(buf)
    view.setUint16(0, 0x8001)  // TPM_ST_NO_SESSIONS
    view.setUint32(2, size)
    view.setUint32(6, commandCode)
    const arr = new Uint8Array(buf)
    arr.set(payload, 10)
    return arr
  }

  private marshalHandle(handle: number): Uint8Array {
    const buf = new ArrayBuffer(4)
    new DataView(buf).setUint32(0, handle)
    return new Uint8Array(buf)
  }

  private marshalTPM2B(data: Uint8Array): Uint8Array {
    const buf = new ArrayBuffer(2 + data.length)
    new DataView(buf).setUint16(0, data.length)
    new Uint8Array(buf).set(data, 2)
    return new Uint8Array(buf)
  }

  private concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((sum, a) => sum + a.length, 0)
    const result = new Uint8Array(total)
    let offset = 0
    for (const a of arrays) {
      result.set(a, offset)
      offset += a.length
    }
    return result
  }
}
```

## PQC Today Integration

### Module Location

```
src/components/PKILearning/modules/SecureBootPQC/workshop/
├── TPMKeyHierarchyExplorer.tsx    # EXISTING — upgrade to live WASM
├── TPMPqcDemo.tsx                 # NEW — ML-DSA/ML-KEM via WASM TPM
├── TPMAttestationDemo.tsx         # NEW — quote/certify with PQC
└── TPMInteropDemo.tsx             # NEW — TPM ↔ softhsmv3 cross-check
```

### Loading Pattern

Follow the existing softhsmv3 WASM loading pattern:

```tsx
import { useEffect, useState } from 'react'
import { PqcTpm } from '@pqctoday/pqctpm-wasm'

function usePqcTpm() {
  const [tpm, setTpm] = useState<PqcTpm | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    PqcTpm.init()
      .then(t => {
        t.startup()
        setTpm(t)
      })
      .catch(setError)
      .finally(() => setLoading(false))
  }, [])

  return { tpm, loading, error }
}
```

### COOP/COEP Headers

Same as softhsmv3 — WASM requires SharedArrayBuffer headers:

```
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
```

Already configured in `vite.config.ts` for the PQC Today dev server.

## Size Budget

| Component | Estimated Size |
|-----------|---------------|
| pqctpm.wasm | ~2-3 MB |
| libcrypto.a (linked in) | ~1.5 MB |
| pqctpm.js (glue) | ~50 KB |
| **Total** | **~3-5 MB** |

For comparison: softhsmv3 C++ WASM = 2.3 MB, Rust WASM = 2.3 MB.

## Testing

```bash
# Unit tests (Node.js)
npx vitest run wasm/pqctpm.test.ts

# Browser test (Playwright)
npx playwright test e2e/tpm-pqc.spec.ts

# Standalone test page
# Open wasm/index.html in browser with COOP/COEP headers
```
