import { getPubKeyPoint, IServiceProvider, IStorageLayer, KEY_NOT_FOUND, MockStorageLayerArgs, StringifiedType } from "@tkey/common-types";
import BN from "bn.js";
import stringify from "json-stable-stringify";

type SaveStorageLayerArgs = {
  dataMap: any;
  serviceProvider: IServiceProvider;
  lockMap: any;
  tkeyHash: string;
  tkeyVersion: string;
};

function generateID(): string {
  // Math.random should be unique because of its seeding algorithm.
  // Convert it to base 36 (numbers + letters), and grab the first 9 characters
  // after the decimal.
  return `${Math.random().toString(36).substr(2, 9)}`;
}
class SaveStorageLayer implements IStorageLayer {
  dataMap: {
    [key: string]: unknown;
  };

  lockMap: {
    [key: string]: string;
  };

  serviceProvider: IServiceProvider;

  filePrefix: string;

  constructor({ dataMap, serviceProvider, lockMap, tkeyHash, tkeyVersion }: SaveStorageLayerArgs) {
    if (!tkeyHash) throw new Error("need tkeyHash")
    this.filePrefix = [tkeyHash, tkeyVersion].join("|")
    this.dataMap = dataMap || {};
    this.serviceProvider = serviceProvider;
    this.lockMap = lockMap || {};
  }

  async save = 

  /**
   *  Get metadata for a key
   * @param privKey If not provided, it will use service provider's share for decryption
   */
  async getMetadata<T>(params: { serviceProvider?: IServiceProvider; privKey?: BN }): Promise<T> {
    const { serviceProvider, privKey } = params;
    let usedKey: BN;
    if (!privKey) usedKey = serviceProvider.retrievePubKeyPoint().getX();
    else usedKey = getPubKeyPoint(privKey).x;

    const fromMap = this.dataMap[usedKey.toString("hex")];
    if (!fromMap) {
      return Object.create({ message: KEY_NOT_FOUND }) as T;
    }
    return JSON.parse(this.dataMap[usedKey.toString("hex")] as string) as T;
  }

  /**
   * Set Metadata for a key
   * @param input data to post
   * @param privKey If not provided, it will use service provider's share for encryption
   */
  async setMetadata<T>(params: { input: T; serviceProvider?: IServiceProvider; privKey?: BN }): Promise<{ message: string }> {
    const { serviceProvider, privKey, input } = params;
    let usedKey: BN;
    if (!privKey) usedKey = serviceProvider.retrievePubKeyPoint().getX();
    else usedKey = getPubKeyPoint(privKey).x;
    this.dataMap[usedKey.toString("hex")] = stringify(input);
    return { message: "success" };
  }

  /**
   * Set Metadata for keys
   * @param input data to post
   * @param privKey If not provided, it will use service provider's share for encryption
   */
  async setMetadataBulk<T>(params: { input: Array<T>; serviceProvider?: IServiceProvider; privKey?: Array<BN> }): Promise<{ message: string }[]> {
    const { serviceProvider, privKey, input } = params;
    input.forEach((el, index) => {
      let usedKey: BN;
      if (!privKey || !privKey[index]) usedKey = serviceProvider.retrievePubKeyPoint().getX();
      else usedKey = getPubKeyPoint(privKey[index]).x;
      this.dataMap[usedKey.toString("hex")] = stringify(el);
    });

    return [{ message: "success" }];
  }

  async acquireWriteLock(params: { serviceProvider?: IServiceProvider; privKey?: BN }): Promise<{ status: number; id?: string }> {
    const { serviceProvider, privKey } = params;
    let usedKey: BN;
    if (!privKey) usedKey = serviceProvider.retrievePubKeyPoint().getX();
    else usedKey = getPubKeyPoint(privKey).x;
    if (this.lockMap[usedKey.toString("hex")]) return { status: 0 };
    const id = generateID();
    this.lockMap[usedKey.toString("hex")] = id;
    return { status: 1, id };
  }

  async releaseWriteLock(params: { id: string; serviceProvider?: IServiceProvider; privKey?: BN }): Promise<{ status: number }> {
    const { serviceProvider, privKey, id } = params;
    let usedKey: BN;
    if (!privKey) usedKey = serviceProvider.retrievePubKeyPoint().getX();
    else usedKey = getPubKeyPoint(privKey).x;
    if (!this.lockMap[usedKey.toString("hex")]) return { status: 0 };
    if (id !== this.lockMap[usedKey.toString("hex")]) return { status: 2 };
    this.lockMap[usedKey.toString("hex")] = null;
    return { status: 1 };
  }

  toJSON(): StringifiedType {
    return {
      dataMap: this.dataMap,
      serviceProvider: this.serviceProvider,
      tkeyHash: this.filePrefix.split("|")[0],
      tkeyVersion: this.filePrefix.split("|")[1],
    };
  }

  static fromJSON(value: StringifiedType): SaveStorageLayer {
    const { dataMap, serviceProvider, lockMap, tkeyHash, tkeyVersion } = value;
    return new SaveStorageLayer({ dataMap, serviceProvider, lockMap, tkeyHash, tkeyVersion });
  }
}

export default SaveStorageLayer;
