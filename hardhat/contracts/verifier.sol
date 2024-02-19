// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x1ac61bd6601baf9bf8614d57a835f56b808156e92e9602877e5d0a4694d08831), uint256(0x0c5c94e82d17fe10f50aea495ede53fe88d63241889fe95f86780d803e45061a));
        vk.beta = Pairing.G2Point([uint256(0x25bd7f047576662748ebcf29618dc465d2ebf8e8ca088eb5df4590ef52c3c2c6), uint256(0x039bce9f8288558d04fb1bb317e1c2623fa7d8032639259afad7441dc604f6ea)], [uint256(0x17e2ff481bd5bd937c0b341583208a4c478bd34548da3eeea4dd025d1479c5da), uint256(0x1e4f9583bdd0d8fb4d8b7707d737f0324cc2a14f290f2a26182ec7efb449e0b9)]);
        vk.gamma = Pairing.G2Point([uint256(0x04cf30f70939def41e4fe697b6b8b9bf9c1d3057d6ec36aee890b8e74da14f82), uint256(0x0422fca965c16d160c29a5fd5faea170e6bd6a7900a3aeb136e494212e8c66a7)], [uint256(0x0afcddcdeb1ed863f4b5f18b8ed312e5242d30583759a09f5bb0514b99863751), uint256(0x1e27eebfb68624d684229012b228ddca5c4d406e9a986a4701c8236e02ede8bb)]);
        vk.delta = Pairing.G2Point([uint256(0x1ba9029fa9aaa7d9cc2c8d95ea6c350b656dcfbdcb3b7d44d6a2154f64940613), uint256(0x10666dfa60b1c5d0aabb15add98db109e61c9377bcc3b4f75685395558794987)], [uint256(0x15d691ef7a0a13d7d1ebc91021575309440cbb1f53aef2773ab7b64c0fcafe2e), uint256(0x04a3f3e217dd10982ba22d689c2b7c2167984bcba4fdd1f2da6e9a1e33bd28e9)]);
        vk.gamma_abc = new Pairing.G1Point[](6);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0e13ff058ab9a7a504e9e4474753596236f921388bf758b9ad273ca96365b58d), uint256(0x2633f5cda110be590a013b0f31de00dacb7dbee66643563a8bd34c7cf87dfd79));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x244bac2ec8b972cfa0953c8c5276b9a9271c6f1bb2381c1e30e209220f147675), uint256(0x0523a29c6709ef90a4cf812d4feb28b30b983477c3063afce9f1dfd3af03e523));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0d1c1bf989034667c1b76ea213a907c41bb505a17c23e9e1c7a070bd217cddc3), uint256(0x1f7709810d32322dadfbf10516a95530817e85efdda926f4a086bd03a10c384f));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x18b9fd6ad177facf05cb9d9ab6b871331e2d8b149f2332de94079f4cd44c59ba), uint256(0x261f5d35d3e58d58c661bfa50aa0f77713604f8b597b7173afb22f4d5572fad6));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1aabc2da48ddb3611917372c77da4bbed8de090df1147446e0fc7573c83acb41), uint256(0x2c8fbbfe8366a8e7ddecc5c743cb87423afe8e99d69f8bd0c1e40d4d9ca46c12));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2015c5bcf561e5b7a80f044688bda0906f0a079b8dfcd6aa04f4822b5a33c375), uint256(0x1e11b656bae6d55eef0270f98fcefcf7afcb91e42eaba40fa6a3b4b675f97ff2));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[5] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](5);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
