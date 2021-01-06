import { ecCurve } from "@tkey/common-types";
import PrivateKeyModule, { SECP256k1Format } from "@tkey/private-keys";
import SecurityQuestionsModule from "@tkey/security-questions";
import SeedPhraseModule, { MetamaskSeedPhraseFormat } from "@tkey/seed-phrase";
import ServiceProviderBase from "@tkey/service-provider-base";
import ShareTransferModule from "@tkey/share-transfer";
import TorusStorageLayer, { MockStorageLayer } from "@tkey/storage-layer-torus";
import { generatePrivate } from "@toruslabs/eccrypto";
import { deepStrictEqual, fail, rejects, strictEqual } from "assert";
import atob from "atob";
import BN from "bn.js";
import btoa from "btoa";
import fetch from "node-fetch";
import { keccak256 } from "web3-utils";
import * as fs from 'fs';

import ThresholdKey from "@tkey/default";

import getPackageVersion from '@jsbits/get-package-version'
 
const tkeyVersion = getPackageVersion("./node_modules/@tkey/core") // ⇒ '1.0.0' (just as example)
if(!tkeyVersion) throw new Error("need tkeyVersion to save")


function initStorageLayer(mocked, extraParams) {
  return mocked === "true" ? new MockStorageLayer({ serviceProvider: extraParams.serviceProvider }) : new TorusStorageLayer(extraParams);
}

const mocked = "true";
const metadataURL = process.env.METADATA || "http://localhost:5051";
const PRIVATE_KEY = "e70fb5f5970b363879bc36f54d4fc0ad77863bfd059881159251f50f48863acf";
const PRIVATE_KEY_2 = "2e6824ef22a58b7b5c8938c38e9debd03611f074244f213943e3fa3047ef2385";

const defaultSP = new ServiceProviderBase({ postboxKey: PRIVATE_KEY });
let defaultSL = initStorageLayer(mocked, { serviceProvider: defaultSP, hostUrl: metadataURL });
let mockLocalStore = {}

global.fetch = fetch;
global.atob = atob;
global.btoa = btoa;

function compareBNArray(a, b, message) {
  if (a.length !== b.length) fail(message);
  return a.map((el, index) => {
    // console.log(el, b[index], el.cmp(b[index]));
    // eslint-disable-next-line no-unused-expressions
    el.cmp(b[index]) !== 0 ? fail(message) : undefined;
    return 0;
  });
}

function compareReconstructedKeys(a, b, message) {
  // eslint-disable-next-line no-unused-expressions
  a.privKey.cmp(b.privKey) !== 0 ? fail(message) : undefined;
  if (a.seedPhraseModule && b.seedPhraseModule) {
    compareBNArray(a.seedPhraseModule, b.seedPhraseModule, message);
  }
  if (a.privateKeyModule && b.privateKeyModule) {
    compareBNArray(a.privateKeyModule, b.privateKeyModule, message);
  }
  if (a.allKeys && b.allKeys) {
    compareBNArray(a.allKeys, b.allKeys, message);
  }
}

async function saveMocks() {
  let filename = [tkeyVersion,this.test.fullTitle().split(" ")[0]].join("|") +".json"
  let dir = "./mocks/"+tkeyVersion
  if (!fs.existsSync(dir)){
    fs.mkdirSync(dir);
  }
  let mocks = {
    dataMap: defaultSL.dataMap,
    localStore: mockLocalStore
  }
  return new Promise((res, rej) => { fs.writeFile(dir+"/"+filename, JSON.stringify(mocks), function(err) {
      if(err) {
          rej(err)
      } else {
          console.log("saved "+filename);
          res("saved "+filename)
      }
  })})
}

async function loadMocks(filepath) {
  let rawdata = fs.readFileSync(filepath);
  defaultSL = new MockStorageLayer({dataMap:JSON.parse(rawdata).dataMap, serviceProvider: defaultSP })
  mockLocalStore = JSON.parse(rawdata).localStore
}


const testAgainstVersions = ["3.4.0"]
async function setupTests() {
  for (let i = 0; i < testAgainstVersions.length; i ++) {
    const dir = './mocks/'+testAgainstVersions[i]
    const files = fs.readdirSync(dir);
    const testSuiteNames = Object.keys(compatibilityTestMap)
    for (let x = 0; x < testSuiteNames.length; x++) {
      for (let j = 0; j < files.length; j++) {
        if (files[j].includes(testSuiteNames[x])) {
          describe("testing "+testSuiteNames[x]+" on "+ files[x], compatibilityTestMap[testSuiteNames[x]](dir+"/"+files[x]))
        }
      }
    }
  }
}


// describe.only("tkey-core", function () {
//   let tb;
//   beforeEach("setup tkey", async function () {
//     // reset mocks
//     mockLocalStore = {}
//     defaultSL = initStorageLayer(mocked, { serviceProvider: defaultSP, hostUrl: metadataURL });
//     tb = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//   });

//   afterEach("save metadata", async function () {
//     await saveMocks.call(this)
//   });

//   it("save standard", async function () {
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.deviceShare);
//     mockLocalStore["deviceShare"] = resp1.deviceShare
//     const reconstructedKey = await tb2.reconstructKey();
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
// });

const compatibilityTestMap = {
  "tkey-core" : function(mockPath) {
    return function () {
    let tb;
    beforeEach("setup tkey", async function () {
      // load new storage layer
      await loadMocks(mockPath)
      tb = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
    });
  
    it("#should be able to reconstruct key when initializing a key", async function () {
      await tb.initialize();
      tb.inputShareStore(mockLocalStore.deviceShare);
      try {
        const reconstructedKey = await tb.reconstructKey();
      } catch (err) {
        fail("key should be able to be reconstructed");
      }
    });
    it("#should be able to generate and delete shares", async function () {
      await tb.initialize();
      tb.inputShareStore(mockLocalStore.deviceShare);
      const reconstructedKey = await tb.reconstructKey();
      const { newShareStores: newShareStores1, newShareIndex: newShareIndex1 } = await tb.generateNewShare();
  
      const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
      await tb2.initialize();
      tb2.inputShareStore(newShareStores1[newShareIndex1.toString("hex")]);
      try {
        const reconstructedKey = await tb2.reconstructKey();
      } catch (err) {
        fail("key should be able to be reconstructed");
      }

      const { newShareStores } = await tb2.deleteShare(newShareIndex1);
      const newKeys = Object.keys(newShareStores);
      if (newKeys.find((el) => el === newShareIndex1.toString("hex"))) {
        fail("Unable to delete share index");
      }
    });
    it("#should not be able to add share post deletion", async function () {
      await tb.initialize();
      tb.inputShareStore(mockLocalStore.deviceShare);
      await tb.reconstructKey();
      const { newShareStores: newShareStores1, newShareIndex: newShareIndex1 } = await tb.generateNewShare();
      await tb.deleteShare(newShareIndex1);
  
      const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
      await tb2.initialize();
      rejects(async () => {
        await tb2.inputShare(newShareStores1[newShareIndex1.toString("hex")].share.share);
      }, Error);
    });
    it("#should be able to reshare a key and retrieve from service provider", async function () {
      await tb.initialize();
      tb.inputShareStore(mockLocalStore.deviceShare);
      const resp1 = await tb.reconstructKey();
      const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
      await tb2.initialize();
      tb2.inputShareStore(mockLocalStore.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
        fail("key should be able to be reconstructed");
      }
      const resp2 = await tb2.generateNewShare();
      const tb3 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
      await tb3.initialize();
      tb3.inputShareStore(resp2.newShareStores[resp2.newShareIndex.toString("hex")]);
      const finalKey = await tb3.reconstructKey();
      if (resp1.privKey.cmp(finalKey.privKey) !== 0) {
        fail("key should be able to be reconstructed after adding new share");
      }
    });
    it("#should be able to reshare a key and retrieve from service provider serialization", async function () {
      await tb.initialize();
      tb.inputShareStore(mockLocalStore.deviceShare);
      const resp1 = await tb.reconstructKey();
      const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
      await tb2.initialize();
      tb2.inputShareStore(mockLocalStore.deviceShare);
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
        fail("key should be able to be reconstructed");
      }
      const resp2 = await tb2.generateNewShare();
      const tb3 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
      await tb3.initialize();
      tb3.inputShareStore(resp2.newShareStores[resp2.newShareIndex.toString("hex")]);
      const finalKey = await tb3.reconstructKey();
      if (resp1.privKey.cmp(finalKey.privKey) !== 0) {
        fail("key should be able to be reconstructed after adding new share");
      }
  
      const stringified = JSON.stringify(tb3);
      const tb4 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: defaultSP, storageLayer: defaultSL });
      const finalKeyPostSerialization = await tb4.reconstructKey();
      strictEqual(finalKeyPostSerialization.toString("hex"), finalKey.toString("hex"), "Incorrect serialization");
    });
    it("#should be able to reconstruct key, even with old metadata", async function () {
      await tb.initialize();
      tb.inputShareStore(mockLocalStore.deviceShare);
      const resp1 = await tb.reconstructKey();
      const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
      await tb2.initialize(); // initialize sdk with old metadata
      tb.generateNewShare(); // generate new share to update metadata
      tb2.inputShareStore(mockLocalStore.deviceShare);
      const reconstructedKey = await tb2.reconstructKey(); // reconstruct key with old metadata should work to poly
      if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
        fail("key should be able to be reconstructed");
      }
    });
  }}
}

setupTests()

// describe("tkey-core", function () {
//   let tb;
//   beforeEach("setup tkey", async function () {
//     // reset storage layer
//     defaultSL = initStorageLayer(mocked, { serviceProvider: defaultSP, hostUrl: metadataURL });
//     tb = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//   });

//   it("#should be able to reconstruct key when initializing a key", async function () {
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstructedKey = await tb2.reconstructKey();
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to reconstruct key when initializing a  with user input", async function () {
//     let determinedShare = new BN(keccak256("user answer blublu").slice(2), "hex");
//     determinedShare = determinedShare.umod(ecCurve.curve.n);
//     const resp1 = await tb.initializeNewKey({ determinedShare, initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.userShare);
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to generate and delete shares", async function () {
//     await tb.initializeNewKey({ initializeModules: true });
//     const { newShareStores: newShareStores1, newShareIndex: newShareIndex1 } = await tb.generateNewShare();
//     const { newShareStores } = await tb.deleteShare(newShareIndex1);

//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     // tb2.inputShareStore(resp1.deviceShare);
//     tb2.inputShareStore(newShareStores1[newShareIndex1.toString("hex")]);
//     const newKeys = Object.keys(newShareStores);
//     if (newKeys.find((el) => el === newShareIndex1.toString("hex"))) {
//       fail("Unable to delete share index");
//     }
//   });
//   it("#should not be able to add share post deletion", async function () {
//     await tb.initializeNewKey({ initializeModules: true });
//     const { newShareStores: newShareStores1, newShareIndex: newShareIndex1 } = await tb.generateNewShare();
//     await tb.deleteShare(newShareIndex1);

//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     rejects(async () => {
//       await tb2.inputShare(newShareStores1[newShareIndex1.toString("hex")].share.share);
//     }, Error);
//   });
//   it("#should be able to reshare a key and retrieve from service provider", async function () {
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstructedKey = await tb2.reconstructKey();
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//     const resp2 = await tb2.generateNewShare();
//     const tb3 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb3.initialize();
//     tb3.inputShareStore(resp2.newShareStores[resp2.newShareIndex.toString("hex")]);
//     const finalKey = await tb3.reconstructKey();
//     if (resp1.privKey.cmp(finalKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed after adding new share");
//     }
//   });
//   it("#should be able to reconstruct key when initializing a with a share ", async function () {
//     let userInput = new BN(keccak256("user answer blublu").slice(2), "hex");
//     userInput = userInput.umod(ecCurve.curve.n);
//     const resp1 = await tb.initializeNewKey({ userInput, initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize({ input: resp1.userShare });
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to reconstruct key after refresh and intializeing with a share ", async function () {
//     let userInput = new BN(keccak256("user answer blublu").slice(2), "hex");
//     userInput = userInput.umod(ecCurve.curve.n);
//     const resp1 = await tb.initializeNewKey({ userInput, initializeModules: true });
//     const newShares = await tb.generateNewShare();
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize({ input: resp1.userShare });
//     tb2.inputShareStore(newShares.newShareStores[resp1.deviceShare.share.shareIndex.toString("hex")]);
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should serialize and deserialize correctly with user input", async function () {
//     let userInput = new BN(keccak256("user answer blublu").slice(2), "hex");
//     userInput = userInput.umod(ecCurve.curve.n);
//     const resp1 = await tb.initializeNewKey({ userInput, initializeModules: true });
//     const newShares = await tb.generateNewShare();
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize({ input: resp1.userShare });
//     tb2.inputShareStore(newShares.newShareStores[resp1.deviceShare.share.shareIndex.toString("hex")]);
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }

//     const stringified = JSON.stringify(tb2);
//     const tb3 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: defaultSP, storageLayer: defaultSL });
//     const finalKey = await tb3.reconstructKey();
//     strictEqual(finalKey.toString("hex"), reconstructedKey.toString("hex"), "Incorrect serialization");
//   });
//   it("#should be able to reshare a key and retrieve from service provider serialization", async function () {
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//     const resp2 = await tb2.generateNewShare();
//     const tb3 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb3.initialize();
//     tb3.inputShareStore(resp2.newShareStores[resp2.newShareIndex.toString("hex")]);
//     const finalKey = await tb3.reconstructKey();
//     // compareBNArray(resp1.privKey, finalKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(finalKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed after adding new share");
//     }

//     const stringified = JSON.stringify(tb3);
//     const tb4 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: defaultSP, storageLayer: defaultSL });
//     const finalKeyPostSerialization = await tb4.reconstructKey();
//     strictEqual(finalKeyPostSerialization.toString("hex"), finalKey.toString("hex"), "Incorrect serialization");
//   });
//   it("#should be able to import and reconstruct an imported key", async function () {
//     const importedKey = new BN(generatePrivate());
//     const resp1 = await tb.initializeNewKey({ importedKey, initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray([importedKey], reconstructedKey, "key should be able to be reconstructed");
//     if (importedKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to reconstruct key, even with old metadata", async function () {
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize(); // initialize sdk with old metadata
//     tb.generateNewShare(); // generate new share to update metadata
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstructedKey = await tb2.reconstructKey(); // reconstruct key with old metadata should work to poly
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to not create a new key if initialize is called with neverInitializeNewKey", async function () {
//     const newSP = new ServiceProviderBase({ postboxKey: new BN(generatePrivate()).toString("hex") });
//     const tb2 = new ThresholdKey({ serviceProvider: newSP, storageLayer: defaultSL });
//     rejects(async () => {
//       await tb2.initialize({ neverInitializeNewKey: true });
//     }, Error);
//   });
// });

// describe("SecurityQuestionsModule", function () {
//   let tb;
//   beforeEach("initialize security questions module", async function () {
//     tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { securityQuestions: new SecurityQuestionsModule() },
//     });
//   });
//   it("#should be able to reconstruct key and initialize a key with security questions", async function () {
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { securityQuestions: new SecurityQuestionsModule() },
//     });
//     await tb2.initialize();

//     await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to reconstruct key and initialize a key with security questions after refresh", async function () {
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { securityQuestions: new SecurityQuestionsModule() },
//     });
//     await tb.generateNewShare();
//     await tb2.initialize();

//     await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to change password", async function () {
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
//     await tb.modules.securityQuestions.changeSecurityQuestionAndAnswer("dodo", "who is your cat?");

//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { securityQuestions: new SecurityQuestionsModule() },
//     });
//     await tb2.initialize();

//     await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("dodo");
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to change password and serialize", async function () {
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
//     await tb.modules.securityQuestions.changeSecurityQuestionAndAnswer("dodo", "who is your cat?");

//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { securityQuestions: new SecurityQuestionsModule() },
//     });
//     await tb2.initialize();

//     await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("dodo");
//     const reconstructedKey = await tb2.reconstructKey();
//     // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }

//     const stringified = JSON.stringify(tb2);
//     const tb4 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: defaultSP, storageLayer: defaultSL });
//     const finalKeyPostSerialization = await tb4.reconstructKey();
//     strictEqual(finalKeyPostSerialization.toString("hex"), reconstructedKey.toString("hex"), "Incorrect serialization");
//   });
// });

// describe("ShareTransferModule", function () {
//   it("#should be able to transfer share via the module", async function () {
//     const tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { shareTransfer: new ShareTransferModule() },
//     });
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { shareTransfer: new ShareTransferModule() },
//     });
//     await tb2.initialize();

//     // usually should be called in callback, but mocha does not allow
//     const pubkey = await tb2.modules.shareTransfer.requestNewShare();

//     // eslint-disable-next-line promise/param-names
//     // await new Promise((res) => {
//     //   setTimeout(res, 200);
//     // });
//     const result = await tb.generateNewShare();
//     await tb.modules.shareTransfer.approveRequest(pubkey, result.newShareStores[result.newShareIndex.toString("hex")]);

//     await tb2.modules.shareTransfer.startRequestStatusCheck(pubkey);
//     // eslint-disable-next-line promise/param-names
//     // await new Promise((res) => {
//     //   setTimeout(res, 1001);
//     // });

//     const reconstructedKey = await tb2.reconstructKey();
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to transfer device share", async function () {
//     const tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { shareTransfer: new ShareTransferModule() },
//     });
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });

//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { shareTransfer: new ShareTransferModule() },
//     });
//     await tb2.initialize();
//     const currentShareIndexes = tb2.getCurrentShareIndexes();
//     // usually should be called in callback, but mocha does not allow
//     const pubkey = await tb2.modules.shareTransfer.requestNewShare("unit test", currentShareIndexes);

//     const requests = await tb.modules.shareTransfer.getShareTransferStore();
//     const pubkey2 = Object.keys(requests)[0];
//     await tb.modules.shareTransfer.approveRequest(pubkey2);

//     await tb2.modules.shareTransfer.startRequestStatusCheck(pubkey, true);

//     // eslint-disable-next-line promise/param-names
//     // await new Promise((res) => {
//     //   setTimeout(res, 1001);
//     // });

//     const reconstructedKey = await tb2.reconstructKey();
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
//   it("#should be able to delete share transfer from another device", async function () {
//     const tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { shareTransfer: new ShareTransferModule() },
//     });
//     await tb.initializeNewKey({ initializeModules: true });

//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { shareTransfer: new ShareTransferModule() },
//     });
//     await tb2.initialize();

//     // usually should be called in callback, but mocha does not allow
//     const encKey2 = await tb2.modules.shareTransfer.requestNewShare();
//     await tb.modules.shareTransfer.deleteShareTransferStore(encKey2); // delete 1st request from 2nd
//     const newRequests = await tb2.modules.shareTransfer.getShareTransferStore();
//     // console.log(newRequests)
//     if (encKey2 in newRequests) {
//       fail("Unable to delete share transfer request");
//     }
//   });
//   it("#should be able to reset share transfer store", async function () {
//     const tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { shareTransfer: new ShareTransferModule() },
//     });
//     await tb.initializeNewKey({ initializeModules: true });

//     await tb.modules.shareTransfer.resetShareTransferStore();
//     const newRequests = await tb.modules.shareTransfer.getShareTransferStore();
//     if (Object.keys(newRequests).length !== 0) {
//       fail("Unable to reset share store");
//     }
//   });
// });

// describe("ShareSerializationModule", function () {
//   it("#should be able to serialize and deserialize share", async function () {
//     const tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//     });
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     const exportedSeedShare = await tb.outputShare(resp1.deviceShare.share.shareIndex, "mnemonic");

//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//     });
//     await tb2.initialize();
//     await tb2.inputShare(exportedSeedShare.toString("hex"), "mnemonic");
//     const reconstructedKey = await tb2.reconstructKey();

//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//   });
// });
// describe("TkeyStore", function () {
//   it("#should get/set seed phrase", async function () {
//     const metamaskSeedPhraseFormat = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
//     const tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat]) },
//     });
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     await tb.modules.seedPhrase.setSeedPhrase("seed sock milk update focus rotate barely fade car face mechanic mercy", "HD Key Tree");

//     const metamaskSeedPhraseFormat2 = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat2]) },
//     });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstuctedKey = await tb2.reconstructKey();
//     // console.log(reconstuctedKey);
//     compareReconstructedKeys(reconstuctedKey, {
//       privKey: resp1.privKey,
//       seedPhraseModule: [new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")],
//       allKeys: [resp1.privKey, new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")],
//     });
//   });
//   it("#should be able to derive keys", async function () {
//     const tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { seedPhrase: new SeedPhraseModule([new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68")]) },
//     });
//     await tb.initializeNewKey({ initializeModules: true });
//     await tb.modules.seedPhrase.setSeedPhrase("seed sock milk update focus rotate barely fade car face mechanic mercy", "HD Key Tree");
//     const actualPrivateKeys = [new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")];
//     const derivedKeys = await tb.modules.seedPhrase.getAccounts();
//     compareBNArray(actualPrivateKeys, derivedKeys, "key should be same");
//   });

//   it("#should be able to get/set private keys", async function () {
//     const privateKeyFormat = new SECP256k1Format();
//     const tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { privateKeyModule: new PrivateKeyModule([privateKeyFormat]) },
//     });
//     await tb.initializeNewKey({ initializeModules: true });

//     const actualPrivateKeys = [
//       new BN("4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390", "hex"),
//       new BN("1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0", "hex"),
//       new BN("7749e59f398c5ccc01f3131e00abd1d061a03ae2ae59c49bebcee61d419f7cf0", "hex"),
//       new BN("1a99651a0aab297997bb3374451a2c40c927fab93903c1957fa9444bc4e2c770", "hex"),
//       new BN("220dad2d2bbb8bc2f731981921a49ee6059ef9d1e5d55ee203527a3157fb7284", "hex"),
//     ];
//     await tb.modules.privateKeyModule.setPrivateKeys(actualPrivateKeys, "secp256k1n");
//     const getAccounts = await tb.modules.privateKeyModule.getAccounts();
//     deepStrictEqual(
//       actualPrivateKeys.map((x) => x.toString("hex")),
//       getAccounts.map((x) => x.toString("hex"))
//     );
//   });

//   it("#should be able to get/set private keys and seed phrase", async function () {
//     const privateKeyFormat = new SECP256k1Format();
//     const metamaskSeedPhraseFormat = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
//     const tb = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat]), privateKeyModule: new PrivateKeyModule([privateKeyFormat]) },
//     });
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });

//     await tb.modules.seedPhrase.setSeedPhrase("seed sock milk update focus rotate barely fade car face mechanic mercy", "HD Key Tree");

//     const actualPrivateKeys = [
//       new BN("4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390", "hex"),
//       new BN("1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0", "hex"),
//       new BN("7749e59f398c5ccc01f3131e00abd1d061a03ae2ae59c49bebcee61d419f7cf0", "hex"),
//       new BN("1a99651a0aab297997bb3374451a2c40c927fab93903c1957fa9444bc4e2c770", "hex"),
//       new BN("220dad2d2bbb8bc2f731981921a49ee6059ef9d1e5d55ee203527a3157fb7284", "hex"),
//     ];
//     await tb.modules.privateKeyModule.setPrivateKeys(actualPrivateKeys, "secp256k1n");

//     const metamaskSeedPhraseFormat2 = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
//     const tb2 = new ThresholdKey({
//       serviceProvider: defaultSP,
//       storageLayer: defaultSL,
//       modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat2]), privateKeyModule: new PrivateKeyModule([privateKeyFormat]) },
//     });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstuctedKey = await tb2.reconstructKey();
//     // console.log(reconstuctedKey);
//     compareReconstructedKeys(reconstuctedKey, {
//       privKey: resp1.privKey,
//       seedPhraseModule: [new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")],
//       privateKeyModule: [
//         new BN("4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390", "hex"),
//         new BN("1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0", "hex"),
//         new BN("7749e59f398c5ccc01f3131e00abd1d061a03ae2ae59c49bebcee61d419f7cf0", "hex"),
//         new BN("1a99651a0aab297997bb3374451a2c40c927fab93903c1957fa9444bc4e2c770", "hex"),
//         new BN("220dad2d2bbb8bc2f731981921a49ee6059ef9d1e5d55ee203527a3157fb7284", "hex"),
//       ],
//       allKeys: [
//         resp1.privKey,
//         new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex"),
//         new BN("4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390", "hex"),
//         new BN("1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0", "hex"),
//         new BN("7749e59f398c5ccc01f3131e00abd1d061a03ae2ae59c49bebcee61d419f7cf0", "hex"),
//         new BN("1a99651a0aab297997bb3374451a2c40c927fab93903c1957fa9444bc4e2c770", "hex"),
//         new BN("220dad2d2bbb8bc2f731981921a49ee6059ef9d1e5d55ee203527a3157fb7284", "hex"),
//       ],
//     });
//   });
// });

// describe("Lock", function () {
//   it("#locks should fail when tkey/nonce is updated ", async function () {
//     const tb = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstructedKey = await tb2.reconstructKey();
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//     await tb2.generateNewShare();
//     let outsideErr;
//     try {
//       await tb.generateNewShare();
//     } catch (err) {
//       outsideErr = err;
//     }
//     if (!outsideErr) {
//       fail("should fail");
//     }
//   });

//   it("#locks should not allow for writes of the same nonce", async function () {
//     const tb = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     const resp1 = await tb.initializeNewKey({ initializeModules: true });
//     const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//     await tb2.initialize();
//     tb2.inputShareStore(resp1.deviceShare);
//     const reconstructedKey = await tb2.reconstructKey();
//     if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
//       fail("key should be able to be reconstructed");
//     }
//     const alltbs = [];
//     // make moar tbs
//     for (let i = 0; i < 5; i += 1) {
//       const temp = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
//       // eslint-disable-next-line no-await-in-loop
//       await temp.initialize();
//       temp.inputShareStore(resp1.deviceShare);
//       // eslint-disable-next-line no-await-in-loop
//       await temp.reconstructKey();
//       alltbs.push(temp);
//     }
//     const promises = [];
//     for (let i = 0; i < alltbs.length; i += 1) {
//       promises.push(alltbs[i].generateNewShare());
//     }
//     const res = await Promise.allSettled(promises);
//     let count = 0;
//     for (let i = 0; i < res.length; i += 1) {
//       if (res[i].status === "fulfilled") count += 1;
//     }
//     if (count !== 1) {
//       fail(count);
//     }
//   });
// });
