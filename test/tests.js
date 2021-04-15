import { ecCurve } from "@tkey/common-types";
import PrivateKeyModule, { SECP256k1Format } from "@tkey/private-keys";
import SecurityQuestionsModule from "@tkey/security-questions";
import SeedPhraseModule, { MetamaskSeedPhraseFormat } from "@tkey/seed-phrase";
import ServiceProviderBase from "@tkey/service-provider-base";
import ShareTransferModule from "@tkey/share-transfer";
import TorusStorageLayer, { MockStorageLayer } from "@tkey/storage-layer-torus";
import { generatePrivate } from "@toruslabs/eccrypto";
import { deepStrictEqual, fail, rejects, strictEqual } from "assert";

import BN from "bn.js";
import * as fs from 'fs';

import ThresholdKey from "@tkey/default";

import getPackageVersion from '@jsbits/get-package-version'


/*
README PLEASE
The aim for this repo is to test if there are any backward incompatibilities in tKey. We achieve this through:
1) Building mocks of metadata:
We output mocks into ./mocks, typically run on new release versions of tKey.
These mocks are designed to represent storage done by tKey, e.g. local storage, metadata, device storage etc...
To add new mocks simply just create a new test suite in the BUILD MOCKS section, it'll be named as its title (i.e. tkey-core => 3.4.0|tkey-core.json )
Naming is important here as we run compatibility tests regexed against the names of the mocks.

2) Running new versions of tKey against these mocks
COMPATIBILITY TESTS section runs the previous created mocks against defined standard scenarios.
We run a wildcard regex on which mocks to run agaisnt, if the test suite is named "tkey-core", we run the tests against all mocks with "tkey-core".
Ideally we build these tests around functionality which we expect from loading storage. For example, loading in an old password from metadata and making changes

In the event of tests tests failing shows incompatibility in versions.
*/
 

// SETUP FUNCTIONS

const tkeyVersion = getPackageVersion("./node_modules/@tkey/core")
if(!tkeyVersion) throw new Error("need tkeyVersion to save")


function initStorageLayer(mocked, extraParams) {
  return mocked === "true" ? new MockStorageLayer({ serviceProvider: extraParams.serviceProvider }) : new TorusStorageLayer(extraParams);
}

const mocked = "true";
const metadataURL = process.env.METADATA || "http://localhost:5051";
const PRIVATE_KEY = "e70fb5f5970b363879bc36f54d4fc0ad77863bfd059881159251f50f48863acf";
const PRIVATE_KEY_2 = "2e6824ef22a58b7b5c8938c38e9debd03611f074244f213943e3fa3047ef2385";
const buildMocks = process.env.BUILD_MOCKS

let testAgainstVersions = fs.readFileSync("./versionsToTest.txt").toString().split(",")
console.log(testAgainstVersions)

const defaultSP = new ServiceProviderBase({ postboxKey: PRIVATE_KEY });
let defaultSL = initStorageLayer(mocked, { serviceProvider: defaultSP, hostUrl: metadataURL });
let mockLocalStore = {}

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
  let titleArr = this.test.title.split(" ")
  let title = titleArr[titleArr.length -1].substring(1, titleArr[titleArr.length -1].length-1)
  let filename = [tkeyVersion,title].join("|") +".json"
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



async function setupTests() {
  for (let i = 0; i < testAgainstVersions.length; i ++) {
    const dir = './mocks/'+testAgainstVersions[i]
    const files = fs.readdirSync(dir);
    const testSuiteNames = Object.keys(compatibilityTestMap)
    for (let x = 0; x < testSuiteNames.length; x++) {
      for (let j = 0; j < files.length; j++) {
        if (files[j].includes(testSuiteNames[x])) {
          describe("testing "+testSuiteNames[x]+" on "+ files[j], compatibilityTestMap[testSuiteNames[x]](dir+"/"+files[j]))
        }
      }
    }
  }
}

/* BUILD MOCKS */

if (buildMocks) {
  describe.only("building mocks", function () {
    let tb;
    beforeEach("reset mocks", async function () {
      // reset mocks
      mockLocalStore = {}
      defaultSL = initStorageLayer(mocked, { serviceProvider: defaultSP, hostUrl: metadataURL });
      
    });
  
    afterEach("save metadata", async function () {
      await saveMocks.call(this)
    });
  
    it("tkey-core", async function () {
      let tb = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
      const resp1 = await tb.initializeNewKey({ initializeModules: true });
      const tb2 = new ThresholdKey({ serviceProvider: defaultSP, storageLayer: defaultSL });
      await tb2.initialize();
      tb2.inputShareStore(resp1.deviceShare);
      mockLocalStore["deviceShare"] = resp1.deviceShare
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
        fail("key should be able to be reconstructed");
      }
    });
  
    it("security-questions", async function () {
      let tb = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      const resp1 = await tb.initializeNewKey({ initializeModules: true });
          await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
          const tb2 = new ThresholdKey({
            serviceProvider: defaultSP,
            storageLayer: defaultSL,
            modules: { securityQuestions: new SecurityQuestionsModule() },
          });
          await tb2.initialize();
      
          await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
          const reconstructedKey = await tb2.reconstructKey();
          // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
          if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
            fail("key should be able to be reconstructed");
          }
    });
  
    it("seedphrase", async function () {
      const metamaskSeedPhraseFormat = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
      const tb = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat]) },
      });
      const resp1 = await tb.initializeNewKey({ initializeModules: true });
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree", "seed sock milk update focus rotate barely fade car face mechanic mercy",);
      mockLocalStore["deviceShare"] = resp1.deviceShare
    });

    it("share-serialization-mnemonic", async function () {
      const tb = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
      });
      const resp1 = await tb.initializeNewKey({ initializeModules: true });
      const exportedSeedShare = await tb.outputShare(resp1.deviceShare.share.shareIndex, "mnemonic");
      mockLocalStore["serializedShare"] = exportedSeedShare
      const tb2 = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
      });
      await tb2.initialize();
      await tb2.inputShare(exportedSeedShare.toString("hex"), "mnemonic");
      const reconstructedKey = await tb2.reconstructKey();
  
      if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
        fail("key should be able to be reconstructed");
      }
    });


  
    // it("tkey-core-seedphrase-security-questions-mix-v3.4.0", async function () {
    //   const metamaskSeedPhraseFormat = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
    //   const tb = new ThresholdKey({
    //     serviceProvider: defaultSP,
    //     storageLayer: defaultSL,
    //     modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat]), securityQuestions: new SecurityQuestionsModule() },
    //   });
    //   const resp1 = await tb.initializeNewKey({ initializeModules: true });
    //   await tb.modules.seedPhrase.setSeedPhrase("seed sock milk update focus rotate barely fade car face mechanic mercy", "HD Key Tree");
    //   await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
    //   const { newShareStores: newShareStores1, newShareIndex: newShareIndex1 } = await tb.generateNewShare()
    //   const { newShareStores } = await tb.deleteShare(resp1.deviceShare.share.shareIndex);
    //   mockLocalStore["deviceShare"] = newShareStores1[newShareIndex1.toString("hex")]
    // });
  });
}


/* COMPATIBILITY TESTS */

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

    it("#should be able to reconstruct key on an SDK with security questions module", async function () {
      tb = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb.initialize();
      tb.inputShareStore(mockLocalStore.deviceShare);
      const resp1 = await tb.reconstructKey();

      await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      const tb2 = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb2.initialize();
  
      await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
      const reconstructedKey = await tb2.reconstructKey();
      if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
        fail("key should be able to be reconstructed");
      }
    });
    it("#should be able to reconstruct key and initialize a key with security questions after refresh", async function () {
      tb = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb.initialize();
      tb.inputShareStore(mockLocalStore.deviceShare);
      const resp1 = await tb.reconstructKey();
      await tb.modules.securityQuestions.generateNewShareWithSecurityQuestions("blublu", "who is your cat?");
      const tb2 = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { securityQuestions: new SecurityQuestionsModule() },
      });
      await tb.generateNewShare();
      await tb2.initialize();
  
      await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
      const reconstructedKey = await tb2.reconstructKey();

      if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
        fail("key should be able to be reconstructed");
      }
    });
    it("#should be able to initialize and set with seedphrase", async function () {
      const metamaskSeedPhraseFormat = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
      const tb = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat]) },
      });
      await tb.initialize();
      tb.inputShareStore(mockLocalStore.deviceShare);
      const resp1 = await tb.reconstructKey();
      await tb.modules.seedPhrase.setSeedPhrase("HD Key Tree", "seed sock milk update focus rotate barely fade car face mechanic mercy");
  
      const metamaskSeedPhraseFormat2 = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
      const tb2 = new ThresholdKey({
        serviceProvider: defaultSP,
        storageLayer: defaultSL,
        modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat2]) },
      });
      await tb2.initialize();
      tb2.inputShareStore(mockLocalStore.deviceShare);
      const reconstuctedKey = await tb2.reconstructKey();
      
      compareReconstructedKeys(reconstuctedKey, {
        privKey: resp1.privKey,
        seedPhraseModule: [new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")],
        allKeys: [resp1.privKey, new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")],
      });
    });
    
  }},
  "security-questions": function(mockPath) {
    return function () {
      let tb;
      beforeEach("initialize security questions module", async function () {
        await loadMocks(mockPath)
        tb = new ThresholdKey({
          serviceProvider: defaultSP,
          storageLayer: defaultSL,
          modules: { securityQuestions: new SecurityQuestionsModule() },
        });
      });
      it("#should be able to reconstruct key with security questions", async function () {
        await tb.initialize();
        await tb.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
        try {
          const reconstructedKey = await tb.reconstructKey();
        } catch (err) {
          fail("key should be able to be reconstructed");
        }
      });
      it("#should be able to change password", async function () {
        await tb.initialize();
        await tb.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
        const resp1 = await tb.reconstructKey()
        await tb.modules.securityQuestions.changeSecurityQuestionAndAnswer("dodo", "who is your cat?");
    
        const tb2 = new ThresholdKey({
          serviceProvider: defaultSP,
          storageLayer: defaultSL,
          modules: { securityQuestions: new SecurityQuestionsModule() },
        });
        await tb2.initialize();
    
        await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("dodo");
        const reconstructedKey = await tb2.reconstructKey();
        if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
          fail("key should be able to be reconstructed");
        }
      });
      it("#should be able to change password and serialize", async function () {
        await tb.initialize();
        await tb.modules.securityQuestions.inputShareFromSecurityQuestions("blublu");
        const resp1 = await tb.reconstructKey()
        await tb.modules.securityQuestions.changeSecurityQuestionAndAnswer("dodo", "who is your cat?");
    
        const tb2 = new ThresholdKey({
          serviceProvider: defaultSP,
          storageLayer: defaultSL,
          modules: { securityQuestions: new SecurityQuestionsModule() },
        });
        await tb2.initialize();
    
        await tb2.modules.securityQuestions.inputShareFromSecurityQuestions("dodo");
        const reconstructedKey = await tb2.reconstructKey();
        // compareBNArray(resp1.privKey, reconstructedKey, "key should be able to be reconstructed");
        if (resp1.privKey.cmp(reconstructedKey.privKey) !== 0) {
          fail("key should be able to be reconstructed");
        }
    
        const stringified = JSON.stringify(tb2);
        const tb4 = await ThresholdKey.fromJSON(JSON.parse(stringified), { serviceProvider: defaultSP, storageLayer: defaultSL });
        const finalKeyPostSerialization = await tb4.reconstructKey();
        strictEqual(finalKeyPostSerialization.toString("hex"), reconstructedKey.toString("hex"), "Incorrect serialization");
      });
    }
  },
  "seedphrase": function(mockPath) {
    return function () {
      beforeEach("load mocks", async function () {
        await loadMocks(mockPath)
      });
      it("#should get seed phrase", async function () {
        const metamaskSeedPhraseFormat2 = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
        const tb2 = new ThresholdKey({
          serviceProvider: defaultSP,
          storageLayer: defaultSL,
          modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat2]) },
        });
        await tb2.initialize();
        tb2.inputShareStore(mockLocalStore.deviceShare);
        const reconstuctedKey = await tb2.reconstructKey();

        compareReconstructedKeys(reconstuctedKey, {
          privKey: reconstuctedKey.privKey,
          seedPhraseModule: [new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")],
          allKeys: [reconstuctedKey.privKey, new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")],
        });
      });
      it("#should be able to derive keys", async function () {
        const tb = new ThresholdKey({
          serviceProvider: defaultSP,
          storageLayer: defaultSL,
          modules: { seedPhrase: new SeedPhraseModule([new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68")]) },
        });
        await tb.initialize();
        tb.inputShareStore(mockLocalStore.deviceShare);
        await tb.reconstructKey()
        const actualPrivateKeys = [new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")];
        const derivedKeys = await tb.modules.seedPhrase.getAccounts();
        compareBNArray(actualPrivateKeys, derivedKeys, "key should be same");
      });
    }
  },
  "share-serialization-mnemonic": function(mockPath) {
    return function () {
      beforeEach("load mocks", async function () {
        await loadMocks(mockPath)
      });
      it("#should be able to accept mnemonic", async function () {
        const tb = new ThresholdKey({
          serviceProvider: defaultSP,
          storageLayer: defaultSL,
        });
        await tb.initialize();
        await tb.inputShare(mockLocalStore.serializedShare, "mnemonic");
        try {
          const reconstructedKey = await tb.reconstructKey();
        } catch (err) {
          fail("key should be able to be reconstructed");
        }
      });
    }
  }
  // "mix-v3.4.0": function(mockPath) {
  //   return function () {
  //     beforeEach("load mocks", async function () {
  //       await loadMocks(mockPath)
  //     });
  //     // it("#should be able to get/set private keys and seed phrase", async function () {
  //     //   const privateKeyFormat = new SECP256k1Format();
  //     //   const metamaskSeedPhraseFormat = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
  //     //   const tb = new ThresholdKey({
  //     //     serviceProvider: defaultSP,
  //     //     storageLayer: defaultSL,
  //     //     modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat]), privateKeyModule: new PrivateKeyModule([privateKeyFormat]) },
  //     //   });
  //     //   const resp1 = await tb.initializeNewKey({ initializeModules: true });
    
  //     //   await tb.modules.seedPhrase.setSeedPhrase("seed sock milk update focus rotate barely fade car face mechanic mercy", "HD Key Tree");
    
  //     //   const actualPrivateKeys = [
  //     //     new BN("4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390", "hex"),
  //     //     new BN("1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0", "hex"),
  //     //     new BN("7749e59f398c5ccc01f3131e00abd1d061a03ae2ae59c49bebcee61d419f7cf0", "hex"),
  //     //     new BN("1a99651a0aab297997bb3374451a2c40c927fab93903c1957fa9444bc4e2c770", "hex"),
  //     //     new BN("220dad2d2bbb8bc2f731981921a49ee6059ef9d1e5d55ee203527a3157fb7284", "hex"),
  //     //   ];
  //     //   await tb.modules.privateKeyModule.setPrivateKeys(actualPrivateKeys, "secp256k1n");
    
  //     //   const metamaskSeedPhraseFormat2 = new MetamaskSeedPhraseFormat("https://mainnet.infura.io/v3/bca735fdbba0408bb09471e86463ae68");
  //     //   const tb2 = new ThresholdKey({
  //     //     serviceProvider: defaultSP,
  //     //     storageLayer: defaultSL,
  //     //     modules: { seedPhrase: new SeedPhraseModule([metamaskSeedPhraseFormat2]), privateKeyModule: new PrivateKeyModule([privateKeyFormat]) },
  //     //   });
  //     //   await tb2.initialize();
  //     //   tb2.inputShareStore(resp1.deviceShare);
  //     //   const reconstuctedKey = await tb2.reconstructKey();
  //     //   // console.log(reconstuctedKey);
  //     //   compareReconstructedKeys(reconstuctedKey, {
  //     //     privKey: resp1.privKey,
  //     //     seedPhraseModule: [new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex")],
  //     //     privateKeyModule: [
  //     //       new BN("4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390", "hex"),
  //     //       new BN("1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0", "hex"),
  //     //       new BN("7749e59f398c5ccc01f3131e00abd1d061a03ae2ae59c49bebcee61d419f7cf0", "hex"),
  //     //       new BN("1a99651a0aab297997bb3374451a2c40c927fab93903c1957fa9444bc4e2c770", "hex"),
  //     //       new BN("220dad2d2bbb8bc2f731981921a49ee6059ef9d1e5d55ee203527a3157fb7284", "hex"),
  //     //     ],
  //     //     allKeys: [
  //     //       resp1.privKey,
  //     //       new BN("70dc3117300011918e26b02176945cc15c3d548cf49fd8418d97f93af699e46", "hex"),
  //     //       new BN("4bd0041b7654a9b16a7268a5de7982f2422b15635c4fd170c140dc4897624390", "hex"),
  //     //       new BN("1ea6edde61c750ec02896e9ac7fe9ac0b48a3630594fdf52ad5305470a2635c0", "hex"),
  //     //       new BN("7749e59f398c5ccc01f3131e00abd1d061a03ae2ae59c49bebcee61d419f7cf0", "hex"),
  //     //       new BN("1a99651a0aab297997bb3374451a2c40c927fab93903c1957fa9444bc4e2c770", "hex"),
  //     //       new BN("220dad2d2bbb8bc2f731981921a49ee6059ef9d1e5d55ee203527a3157fb7284", "hex"),
  //     //     ],
  //     //   });
  //     // });
  //   }
  // }
}

setupTests()


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

