export type Keystore = { iv: string; data: string; }

export default class Crypto {
  static internalCrypto = globalThis.crypto
  private static instance: Crypto | null = null

  public static getInstance(): Crypto {
    if(this.instance === null) {
      this.instance = new Crypto()
    }

    return this.instance
  }

  public randomBytes(length: number): Uint8Array {
    return Crypto.internalCrypto.getRandomValues(new Uint8Array(length))
  }

  public async hashString(msg: string): Promise<string> {
    const u8 = new TextEncoder().encode(msg)
    const buffer = await Crypto.internalCrypto.subtle.digest('SHA-256', u8)
    const arr = new Uint8Array(buffer)

    let str = ''
    for (let i = 0; i < arr.length; i++) {
      str += arr[i].toString(16).padStart(2, '0')
    }

    return str
  }

  public async hash(msg: string): Promise<ArrayBuffer> {
    const u8 = new TextEncoder().encode(msg)
    const buffer = await Crypto.internalCrypto.subtle.digest('SHA-256', u8)
    return buffer
  }

  public buffer2hex(buffer: ArrayBuffer | Uint8Array): string {
    let bin = ''
    let arr = new Uint8Array(buffer)
    for (let i=0; i<arr.length; i++) {
      bin = bin + arr[i].toString(16).padStart(2, '0')
    }
    return bin
  }

  public hex2buffer(str: string): Uint8Array {
    const arr: number[] = []
    for(let i=0; i<str.length; i+=2) {
      arr.push(parseInt(str.slice(i, i+2), 16))
    }
    return new Uint8Array(arr)
  }

  public async deriveKeyPBKDF2(pwd: string, salt: Uint8Array<any> | null = null): Promise<{salt: Uint8Array, key: ArrayBuffer}> {
    const enc = new TextEncoder()
    // 16 bytes salt
    if(salt === null) {
      salt = Crypto.internalCrypto.getRandomValues(new Uint8Array(16))
    }

    const keyMaterial = await Crypto.internalCrypto.subtle.importKey(
      'raw',
      enc.encode(pwd),
      {name: 'PBKDF2'},
      false,
      ["deriveBits"]
    )

    const bits = await Crypto.internalCrypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: 600000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256 // 32 bytes
    )

    return {
      salt: salt,
      key: bits
    }
  }

  public async encrypt(msg: string, pwd: string): Promise<Keystore | null> {
    try {
      const iv = Crypto.internalCrypto.getRandomValues(new Uint8Array(12))
      const data = new TextEncoder().encode(msg)

      const hash = await this.deriveKeyPBKDF2(pwd, null)
      const key = await Crypto.internalCrypto.subtle.importKey(
        'raw',
        hash.key,
        {name: 'AES-GCM'},
        false,
        ['encrypt']
      )
      const rs = await Crypto.internalCrypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv
        },
        key,
        data
      )

      const saltIV = new Uint8Array(hash.salt.length + iv.length)
      saltIV.set(hash.salt, 0)
      saltIV.set(iv, hash.salt.length)

      return {
        iv: this.buffer2hex(saltIV),
        data: this.buffer2hex(rs)
      }
    } catch(e) {}

    return null
  }

  public async decrypt(cipher: Keystore, pwd: string): Promise<string> {
    try {
      const saltIV = cipher.iv
      const data = cipher.data
      const salt = saltIV.slice(0, 32)
      const iv = saltIV.slice(32)

      const hash = await this.deriveKeyPBKDF2(pwd, this.hex2buffer(salt))
      const key = await Crypto.internalCrypto.subtle.importKey(
        'raw',
        hash.key,
        {name: 'AES-GCM'},
        false,
        ['decrypt']
      )
      const decrypted = await Crypto.internalCrypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: this.hex2buffer(iv).buffer as ArrayBuffer
        },
        key,
        this.hex2buffer(data).buffer as ArrayBuffer
      )

      return new TextDecoder().decode(decrypted)
    } catch(e) {}

    return ''
  }
}
