import { Verifier } from "../typechain-types/verifier.sol/Verifier.js";
import {
  time,
  loadFixture,
} from "@nomicfoundation/hardhat-toolbox/network-helpers.js";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs.js";
import * as fs from 'fs';
import battleFieldFactoryPackage from "../typechain-types/factories/BattleField__factory.js";
import { BattleField } from "../typechain-types/BattleField.js";
import hardhat from "hardhat";
import { expect } from "chai";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers.js";
import { initialize } from "zokrates-js";
import { BigNumberish } from "ethers";
import { base64ToArrayBuffer } from "./base64ToArrayBuffer.js";

describe("Battleship", function() { 
  let battleField: BattleField
  let attacker: HardhatEthersSigner
  let defender: HardhatEthersSigner
  
  beforeEach(async () => {    
    let [deployer, a, d] = await hardhat.ethers.getSigners();
    battleField = await new battleFieldFactoryPackage.BattleField__factory(deployer).deploy();
    attacker = a;
    defender = d;
  })

  it("Should Convert Hashes correctly", async function() {    
    const args = [2,2,0];

    const expectedHashPart1 = BigInt("86380206906175785665172669475566779147");
    const expectedHashPart2 = BigInt("307841847181429311680751566479984471896");

    let ethersHash = hardhat.ethers.solidityPackedKeccak256(new Array(3).fill("uint8"), args);
    let concattedHash = await battleField.concatHash(expectedHashPart1, expectedHashPart2);
    let hashBack = await battleField.splitHash(concattedHash);

    expect(expectedHashPart1).to.be.equal(hashBack[0]);
    expect(expectedHashPart2).to.be.equal(hashBack[1]);
    expect(ethersHash).to.be.equal(concattedHash);
  }),

  it("Should allow to attack and verify the attack", async function() {
    const attackFalseX = 2;
    const attackFalseY = 3;
    const crX = 5;
    const crY = 10;
    const spX = 9;
    const spY = 7;
    const coordinates = [crX, crY, spX, spY]; // x y & orientation
    const coordinatesHash = hardhat.ethers.solidityPackedKeccak256(new Array(coordinates.length).fill("uint8"), coordinates);
    const gameID = 1;

    battleField.connect(defender).CreateBattleField(coordinatesHash, gameID);

    // attacks
    battleField.connect(attacker).AttackField(defender, gameID, attackFalseX, attackFalseY, 1);
    battleField.connect(attacker).AttackField(defender, gameID, crX, crY, 2);

    // init
    let zokratesProvider = await initialize();
    let fieldCode = await fs.promises.readFile("./contracts/field.zok").then(i => i.toString());
    let provingKey = await fs.promises.readFile("./contracts/proving.key").then(i => i.toString("hex"));
    let artifacts = zokratesProvider.compile(fieldCode);

    async function generateAndSubmitProof(attackX:number, attackY:number, index:number, resultToProve: boolean) {
      // gathering args and computing witness
      const splitHash = await battleField.splitHash(coordinatesHash);

      console.log("splitHash:", splitHash);

      const args = [...coordinates.map(i => i.toString()), ...splitHash.map(i => i.toString()), attackX.toString(), attackY.toString(), resultToProve];
      const { witness, output } = zokratesProvider.computeWitness(artifacts, args);
      const { proof } = zokratesProvider.generateProof(artifacts.program, witness, base64ToArrayBuffer(provingKey));

      await battleField.VerifyAttack(proof as Verifier.ProofStruct, index, resultToProve);
      const fieldState1 = await battleField.battlefieldStates(coordinatesHash, attackX, attackY);
      expect(fieldState1).to.equal(resultToProve ? '1' : '2'); // 2 = MISS
    }

    // attack results
    await generateAndSubmitProof(attackFalseX, attackFalseY, 1, false);
    await generateAndSubmitProof(crX, crY, 2, true);
  })
});