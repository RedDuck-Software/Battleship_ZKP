# Battlefield game - Learning ZK Technology through Zokrates

Some notes:
1. Verifier and Prover key are public, Zokrates code is translated into Solidity contract with hardcoded Verifier key, they are not modifiable.
2. User uses prover key to create zero knowledge proofs and submit them to the contract.
3. You should write your non-ZK logic on top of the verifyTX function. 
4. We can’t just write (carrierX == attackIndexX && carrierY == attackIndexY) because we also need the Boolean variable to be available in solidity. That’s why we add a public variable bool and make comparison == 
5. Next challenge - combining two uint256 values into one, or splitting one into two. Possibly just >> or +. https://ethereum.stackexchange.com/questions/72341/how-to-concatenate-two-bytes16-to-bytes32 . Implemented in the smart-contract code.
6. keccak is not easily available through zokrates, so I wrote a wrapper over its implementation so it is easy to use 
7. Upon adding the zokrates module: ERR_REQUIRE_ESM =  https://stackoverflow.com/questions/69081410/error-err-require-esm-require-of-es-module-not-supported
8. HardhatError: HH19: https://github.com/NomicFoundation/hardhat/issues/3385
9.   Perform steps in the message including code adjustments
10. Architecture - smart-contracts are submitting public data, not frontend, as zok has no access to transaction metadata (such as msg.sender etc.)
11. Example from https://github.com/tomoima525/zkp-vote/blob/main/src/pages/index.tsx#L99 is incorrect. The correct is to use Uint8() as here https://github.com/Zokrates/zokrates-nextjs-demo/blob/main/src/pages/index.tsx#L75 
12. Do NOT save compiled .zok files!!! They are too large to commit.