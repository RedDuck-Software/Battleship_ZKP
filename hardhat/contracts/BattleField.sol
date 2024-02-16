// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./verifier.sol";
import "../node_modules/hardhat/console.sol";

contract BattleField is Verifier {
    enum CoordinateState {
        NONE,
        HIT,
        MISS
    }

    struct Attack {
        bool initialized;
        address Attacker;
        address Defender;
        uint256 X;
        uint256 Y;
        CoordinateState State;
        uint256 gameID;
    }

    // user -> gameID -> battleField Hash
    mapping (address => mapping(uint256 => bytes32)) battlefieldHashes;
    // attackID -> attack info (x, y, state, addresses)
    mapping (uint256 => Attack) public attacks;
    // battleField Hash -> X -> Y -> Hit/Miss/NONE
    mapping (bytes32 => mapping(uint256 => mapping(uint256 => CoordinateState))) public battlefieldStates;

    function concatHash(uint256 a, uint256 b) public pure returns (bytes32) {
        return bytes32 (uint256 (uint128 (a)) << 128 | uint128 (b));
    }

    function splitHash(bytes32 x) public pure returns (uint256 a, uint256 b) {
        a = uint256(x >> 128);
        b = uint256((x << 128) >> 128);

        return (a, b);
    }

    function CreateBattleField(bytes32 fieldHash, uint256 gameID) external {
        require(battlefieldHashes[msg.sender][gameID] == bytes32(0), "already set");

        battlefieldHashes[msg.sender][gameID] = fieldHash;
    }

    function AttackField(address player, uint256 gameID, uint256 x, uint256 y, uint256 attackID) external {
        require(!attacks[attackID].initialized, "already attacked");

        attacks[attackID] = Attack(true, msg.sender, player, x, y, CoordinateState.NONE, gameID);
    }

    function VerifyAttack(Proof memory proof, uint256 attackID, bool success) public {
        Attack memory attack = attacks[attackID];
        require(attack.initialized, "attack doesn't exist");
        require(attack.State == CoordinateState.NONE, "alreaedy processed attack");

        bytes32 battlefieldHash = battlefieldHashes[attack.Defender][attack.gameID];
        console.log("battleFieldHash:");
        console.logBytes32(battlefieldHash);

        (uint256 a, uint256 b) = splitHash(battlefieldHash);

        // hash1, hash2, x, y, true/false
        uint[5] memory input = [a, b, attack.X, attack.Y, success ? 1 : 0];
        console.log("input: a: %s b: %s x: %s", a, b, attack.X);
        console.log("input: y: %s, success: %s", attack.Y, success ? 1 : 0);

        bool result = verifyTx(proof, input);

        require (result, "proof");

        if (result) {
            CoordinateState state = success ? CoordinateState.HIT : CoordinateState.MISS;
            attacks[attackID].State = state;
            battlefieldStates[battlefieldHash][attack.X][attack.Y] = state;
        }
    }    
}
