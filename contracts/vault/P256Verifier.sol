// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title P256Verifier
 * @notice NIST P-256 (secp256r1) ECDSA signature verification library.
 *
 * @dev Attempts the RIP-7212 precompile at address(0x100) first.
 *      Falls back to pure-Solidity verification using Jacobian coordinates,
 *      Shamir's trick, and the MODEXP precompile (0x05) for modular inverse.
 *
 * Curve parameters (NIST P-256 / secp256r1):
 *   P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
 *   N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 *   A  = P - 3
 *   B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
 *   GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
 *   GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
 */
library P256Verifier {
    // =========================================================================
    // CURVE CONSTANTS
    // =========================================================================

    uint256 internal constant P =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 internal constant N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant A =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC; // P - 3
    uint256 internal constant B =
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    uint256 internal constant GX =
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 internal constant GY =
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

    /// @notice RIP-7212 precompile address for P-256 verification.
    address internal constant RIP7212 = address(0x100);

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /**
     * @notice Verify a P-256 ECDSA signature.
     * @param hash The SHA-256 hash of the message.
     * @param r    Signature component r.
     * @param s    Signature component s.
     * @param qx   Public key x-coordinate.
     * @param qy   Public key y-coordinate.
     * @return True if the signature is valid.
     */
    function verify(
        bytes32 hash,
        uint256 r,
        uint256 s,
        uint256 qx,
        uint256 qy
    ) internal view returns (bool) {
        // Try RIP-7212 precompile first
        (bool precompileOk, bool precompileResult) = _tryPrecompile(hash, r, s, qx, qy);
        if (precompileOk) return precompileResult;

        // Fallback to pure-Solidity verification
        return _verifySolidity(hash, r, s, qx, qy);
    }

    // =========================================================================
    // RIP-7212 PRECOMPILE
    // =========================================================================

    function _tryPrecompile(
        bytes32 hash,
        uint256 r,
        uint256 s,
        uint256 qx,
        uint256 qy
    ) private view returns (bool ok, bool valid) {
        bytes memory input = abi.encode(hash, r, s, qx, qy);
        (bool success, bytes memory output) = RIP7212.staticcall(input);
        if (success && output.length >= 32) {
            uint256 result = abi.decode(output, (uint256));
            return (true, result == 1);
        }
        return (false, false);
    }

    // =========================================================================
    // PURE-SOLIDITY FALLBACK
    // =========================================================================

    function _verifySolidity(
        bytes32 hash,
        uint256 r,
        uint256 s,
        uint256 qx,
        uint256 qy
    ) private view returns (bool) {
        // 1. Range checks
        if (r == 0 || r >= N) return false;
        if (s == 0 || s >= N) return false;

        // 2. Compute s^(-1) mod N
        uint256 sInv = _modInv(s, N);
        if (sInv == 0) return false;

        // 3. Compute u1 = hash * sInv mod N and u2 = r * sInv mod N
        uint256 u1 = mulmod(uint256(hash), sInv, N);
        uint256 u2 = mulmod(r, sInv, N);

        // 4. Compute R = u1*G + u2*Q using Shamir's trick
        if (u1 == 0 && u2 == 0) return false;

        (uint256 rx, ) = _shamirMultiply(u1, u2, qx, qy);

        // 5. Check x-coordinate
        return (rx % N) == r;
    }

    // =========================================================================
    // MODULAR INVERSE VIA MODEXP PRECOMPILE
    // =========================================================================

    /**
     * @dev Compute a^(m-2) mod m using the MODEXP precompile (Fermat's little theorem).
     *      m must be prime.
     */
    function _modInv(uint256 a, uint256 m) private view returns (uint256 result) {
        // MODEXP precompile at 0x05
        // Input: [base_len (32), exp_len (32), mod_len (32), base, exp, mod]
        uint256 exponent = m - 2;

        assembly {
            let ptr := mload(0x40)
            // base_len = 32
            mstore(ptr, 0x20)
            // exp_len = 32
            mstore(add(ptr, 0x20), 0x20)
            // mod_len = 32
            mstore(add(ptr, 0x40), 0x20)
            // base = a
            mstore(add(ptr, 0x60), a)
            // exp = m - 2
            mstore(add(ptr, 0x80), exponent)
            // mod = m
            mstore(add(ptr, 0xa0), m)

            // Call MODEXP precompile at address 0x05
            let success := staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)
            if iszero(success) {
                // Should never happen for valid inputs
                result := 0
            }
            result := mload(ptr)
        }
    }

    // =========================================================================
    // SHAMIR'S TRICK: u1*G + u2*Q
    // =========================================================================

    /**
     * @dev Computes u1*G + u2*Q efficiently using Shamir's trick.
     *      Precomputes G+Q and iterates bits of u1 and u2 simultaneously.
     *      Returns the affine x,y coordinates of the result.
     */
    function _shamirMultiply(
        uint256 u1,
        uint256 u2,
        uint256 qx,
        uint256 qy
    ) private view returns (uint256, uint256) {
        // Precompute G + Q (affine)
        (uint256 gqx, uint256 gqy) = _ecAffineAdd(GX, GY, qx, qy);

        // Start with point at infinity (Jacobian: Z=0)
        uint256 rx = 0;
        uint256 ry = 0;
        uint256 rz = 0;

        // Iterate from the highest bit down to bit 0
        // P-256 order N is 256 bits, so we scan all 256 bits
        for (uint256 i = 256; i > 0; ) {
            unchecked { --i; }

            // Double current point
            if (rz != 0) {
                (rx, ry, rz) = _jacDouble(rx, ry, rz);
            }

            uint256 b1 = (u1 >> i) & 1;
            uint256 b2 = (u2 >> i) & 1;

            if (b1 == 1 && b2 == 1) {
                // Add G+Q
                if (rz == 0) {
                    (rx, ry, rz) = (gqx, gqy, 1);
                } else {
                    (rx, ry, rz) = _jacMixedAdd(rx, ry, rz, gqx, gqy);
                }
            } else if (b1 == 1) {
                // Add G
                if (rz == 0) {
                    (rx, ry, rz) = (GX, GY, 1);
                } else {
                    (rx, ry, rz) = _jacMixedAdd(rx, ry, rz, GX, GY);
                }
            } else if (b2 == 1) {
                // Add Q
                if (rz == 0) {
                    (rx, ry, rz) = (qx, qy, 1);
                } else {
                    (rx, ry, rz) = _jacMixedAdd(rx, ry, rz, qx, qy);
                }
            }
            // else: both bits are 0, just double (already done above)
        }

        if (rz == 0) return (0, 0); // Point at infinity

        // Convert Jacobian to affine
        return _jacToAffine(rx, ry, rz);
    }

    // =========================================================================
    // JACOBIAN POINT DOUBLING (a = P - 3 optimization)
    // =========================================================================

    /**
     * @dev Point doubling in Jacobian coordinates.
     *      Optimized for a = -3 (mod P), i.e., a = P - 3.
     *
     *      M = 3 * (X + Z^2) * (X - Z^2)    [since a = -3]
     *      S = 4 * X * Y^2
     *      X' = M^2 - 2*S
     *      Y' = M * (S - X') - 8 * Y^4
     *      Z' = 2 * Y * Z
     */
    function _jacDouble(
        uint256 x,
        uint256 y,
        uint256 z
    ) private pure returns (uint256 x3, uint256 y3, uint256 z3) {
        if (z == 0) return (0, 0, 0);

        uint256 zz = mulmod(z, z, P); // Z^2
        uint256 xPlusZZ = addmod(x, zz, P); // X + Z^2
        uint256 xMinusZZ = addmod(x, P - zz, P); // X - Z^2

        // M = 3 * (X + Z^2) * (X - Z^2)
        uint256 m = mulmod(xPlusZZ, xMinusZZ, P);
        m = mulmod(3, m, P);

        uint256 yy = mulmod(y, y, P); // Y^2
        // S = 4 * X * Y^2
        uint256 s = mulmod(4, mulmod(x, yy, P), P);

        // X' = M^2 - 2*S
        x3 = addmod(mulmod(m, m, P), P - addmod(s, s, P), P);

        // Y' = M * (S - X') - 8 * Y^4
        uint256 yyyy = mulmod(yy, yy, P); // Y^4
        y3 = addmod(
            mulmod(m, addmod(s, P - x3, P), P),
            P - mulmod(8, yyyy, P),
            P
        );

        // Z' = 2 * Y * Z
        z3 = mulmod(2, mulmod(y, z, P), P);
    }

    // =========================================================================
    // MIXED JACOBIAN + AFFINE ADDITION
    // =========================================================================

    /**
     * @dev Add a Jacobian point (x1, y1, z1) and an affine point (x2, y2).
     *      Assumes (x2, y2) is NOT the point at infinity.
     *
     *      U1 = X1,   U2 = X2 * Z1^2
     *      S1 = Y1,   S2 = Y2 * Z1^3
     *      H = U2 - U1,  R = S2 - S1
     *
     *      If H == 0 and R == 0: it's a doubling case.
     *      If H == 0 and R != 0: result is point at infinity.
     *
     *      X3 = R^2 - H^3 - 2*U1*H^2
     *      Y3 = R*(U1*H^2 - X3) - S1*H^3
     *      Z3 = H * Z1
     */
    function _jacMixedAdd(
        uint256 x1,
        uint256 y1,
        uint256 z1,
        uint256 x2,
        uint256 y2
    ) private pure returns (uint256 x3, uint256 y3, uint256 z3) {
        if (z1 == 0) return (x2, y2, 1);

        uint256 z1z1 = mulmod(z1, z1, P); // Z1^2
        uint256 u2 = mulmod(x2, z1z1, P); // U2 = X2 * Z1^2
        uint256 s2 = mulmod(y2, mulmod(z1, z1z1, P), P); // S2 = Y2 * Z1^3

        uint256 h = addmod(u2, P - x1, P); // H = U2 - U1 (U1 = X1 for mixed)
        uint256 r = addmod(s2, P - y1, P); // R = S2 - S1 (S1 = Y1 for mixed)

        if (h == 0) {
            if (r == 0) {
                // Same point — double it
                return _jacDouble(x1, y1, z1);
            } else {
                // Point at infinity
                return (0, 0, 0);
            }
        }

        uint256 hh = mulmod(h, h, P);     // H^2
        uint256 hhh = mulmod(h, hh, P);    // H^3
        uint256 u1hh = mulmod(x1, hh, P);  // U1 * H^2

        // X3 = R^2 - H^3 - 2 * U1 * H^2
        x3 = addmod(
            mulmod(r, r, P),
            P - addmod(hhh, addmod(u1hh, u1hh, P), P),
            P
        );

        // Y3 = R * (U1*H^2 - X3) - S1 * H^3
        y3 = addmod(
            mulmod(r, addmod(u1hh, P - x3, P), P),
            P - mulmod(y1, hhh, P),
            P
        );

        // Z3 = H * Z1
        z3 = mulmod(h, z1, P);
    }

    // =========================================================================
    // AFFINE POINT ADDITION (for precomputing G+Q)
    // =========================================================================

    /**
     * @dev Add two affine points. Returns affine result.
     *      Does not handle point at infinity or equal points well,
     *      but that's fine for precomputing G+Q (they are different known points).
     */
    function _ecAffineAdd(
        uint256 x1,
        uint256 y1,
        uint256 x2,
        uint256 y2
    ) private view returns (uint256 x3, uint256 y3) {
        if (x1 == x2) {
            if (y1 == y2) {
                // Point doubling in affine
                return _ecAffineDbl(x1, y1);
            } else {
                // x1 == x2 but y1 != y2 => point at infinity
                return (0, 0);
            }
        }

        // lambda = (y2 - y1) / (x2 - x1) mod P
        uint256 num = addmod(y2, P - y1, P);
        uint256 den = addmod(x2, P - x1, P);
        uint256 lambda = mulmod(num, _modInv(den, P), P);

        // x3 = lambda^2 - x1 - x2
        x3 = addmod(mulmod(lambda, lambda, P), P - addmod(x1, x2, P), P);
        // y3 = lambda * (x1 - x3) - y1
        y3 = addmod(mulmod(lambda, addmod(x1, P - x3, P), P), P - y1, P);
    }

    /**
     * @dev Affine point doubling.
     */
    function _ecAffineDbl(
        uint256 x1,
        uint256 y1
    ) private view returns (uint256 x3, uint256 y3) {
        // lambda = (3*x1^2 + a) / (2*y1) mod P
        // With a = P - 3:
        uint256 xx = mulmod(x1, x1, P);
        uint256 num = addmod(mulmod(3, xx, P), A, P);
        uint256 den = mulmod(2, y1, P);
        uint256 lambda = mulmod(num, _modInv(den, P), P);

        // x3 = lambda^2 - 2*x1
        x3 = addmod(mulmod(lambda, lambda, P), P - addmod(x1, x1, P), P);
        // y3 = lambda * (x1 - x3) - y1
        y3 = addmod(mulmod(lambda, addmod(x1, P - x3, P), P), P - y1, P);
    }

    // =========================================================================
    // JACOBIAN TO AFFINE CONVERSION
    // =========================================================================

    /**
     * @dev Convert Jacobian (X, Y, Z) to affine (x, y).
     *      x = X / Z^2,  y = Y / Z^3
     */
    function _jacToAffine(
        uint256 x,
        uint256 y,
        uint256 z
    ) private view returns (uint256 ax, uint256 ay) {
        uint256 zInv = _modInv(z, P);
        uint256 zInv2 = mulmod(zInv, zInv, P);
        uint256 zInv3 = mulmod(zInv2, zInv, P);
        ax = mulmod(x, zInv2, P);
        ay = mulmod(y, zInv3, P);
    }
}
