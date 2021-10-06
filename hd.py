#
# HD Wallet Example (BIP 39)
#
# https://www.freecodecamp.org/news/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f/
# https://www.oreilly.com/library/view/mastering-bitcoin/9781491902639/ch04.html
#
# Author: redd
#


#
# To Do
# * I can create P2PKH from mnemonics and private keys, but I haven't confirmed I can create them from paper wallets using WIF
#     Use https://www.athenabitcoin.com/news/2018/4/9/how-to-use-a-paper-wallet for WIF 5Jy7Pjm961LGR9HD7zW2nrMbXitrPose38nFhmJgaU91aibY8b5 to 1HwWGwdzk5Ed7sMjpn9kadJQs5VEZ192wa
# * Go all the way from mneumoics to Bech32 addresses.


#
# Notes
# * Why does the entropy and seed phrase match, but not seed at https://www.oreilly.com/library/view/mastering-bitcoin/9781491902639/ch04.html
#     Because they're wrong. I was able to rederive addresses using the seed phrase as shown in electrum.
#

import hmac
import hashlib
import ecdsa
import base58
import mnemonic


class Key:
    def __init__(self) -> None:
        self.privkey = bytes(32)
        self.pubkey = bytes(32) # self.calcPubKey()
        self.chaincode = bytes(32)

    def calcPubKey(self):
        sk = ecdsa.SigningKey.from_string(self.privkey, curve=ecdsa.SECP256k1) # signing key
        vk = sk.get_verifying_key().to_string() # verifying key
        vk = b'\x03' + vk[:32] if int(vk[-1]) % 2 else b'\x02' + vk[:32]
        return vk

    def __repr__(self) -> str:
        return f"Private key: {self.privkey.hex()}\nPublic key:  {self.pubkey.hex()}\nChain code:  {self.chaincode.hex()}\n"


class MasterKey(Key):
    def __init__(self, seed) -> None:
        m = hmac.new(b"Bitcoin seed",seed,hashlib.sha512).digest() # master key
        self.privkey = m[:32] # master private key
        self.pubkey = self.calcPubKey() # Figure this out.
        self.chaincode = m[32:] # chain code


class ChildKey(Key):
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    def __init__(self, parent, n, hardened) -> None:
        if hardened:
            x = hmac.new(parent.chaincode, bytes.fromhex('00') + parent.privkey + int(2**31+n).to_bytes(4,'big'), hashlib.sha512).digest()
            y = int.from_bytes(parent.privkey,'big') + int.from_bytes(x[:32],'big')
            self.privkey = int(y % self.N).to_bytes(32,'big')
            self.chaincode = x[32:]
        else:
            x = hmac.new(parent.chaincode, parent.pubkey + int(n).to_bytes(4,'big'), hashlib.sha512).digest()
            y = int.from_bytes(parent.privkey,'big') + int.from_bytes(x[:32],'big')
            self.privkey = int(y % self.N).to_bytes(32,'big')
            self.chaincode = x[32:]
        
        self.pubkey = self.calcPubKey()


def deriveFromPath(seed, dp):
    """
    seed is entropy in bytes
    dp is the derivation path, like "m/44'/0'/0'/0/0"
    """
    dp = dp.split("/") # derivation path
    k = None
    for p in dp:
        l = p.split("'")
        if l[0] == 'm':
            k = MasterKey(seed)
        else:
            n = int(l[0])
            hardened = len(l) == 2
            k = ChildKey(k, n, hardened)
    return k


def test_derivation():
    # tests
    seed = bytes.fromhex('65729d81d461591bac7384dea43dbd44438053cd1fdc113e0769c49c5fde025ba331eed2077497634e619948437d0448e769a86c0cbbecf01b13fd53540743b3')
    m = deriveFromPath(seed, "m")
    assert m.privkey.hex() == 'a0ccf14c939faa07b896cd5fb306a37fb3f9cb041196c5364d0cca9dbd82e53a'
    assert m.pubkey.hex() == '03d1cc1f6bdea4d17eb7f2573d676f9ddb087f8b784c912c4466407781d8acfe38'
    assert m.chaincode.hex() == '5bc9d1368631ae579f02ed8e46a56dd9dd9de8ac59e3c4e18247ff96988bdf1f'

    m_44h = deriveFromPath(seed, "m/44'")
    assert m_44h.privkey.hex() == '2096bf7f3a4ea9c667e7255219f77a6e5ccedba2546abbcfc9468a4925f5221d'
    assert m_44h.pubkey.hex() == '03fa6d455fc978f88b9a96df4e9aaa2755d79f763c98662eaec9d4213c4b91175e'
    assert m_44h.chaincode.hex() == '81d4b120fcd3a11837e5d035fc508bb8b31c47285fdd7506d8d264144b4d8df7'

    m_44h_0h = deriveFromPath(seed, "m/44'/0'")
    assert m_44h_0h.privkey.hex() == 'ff7b844a9ca9d1b899007245d8f62154d741edd1cc1204895144779c59bf8614'
    assert m_44h_0h.pubkey.hex() == '028cbc52cf2e1d6fac7ddd80c5963ab5d637d032c6c5b5f25ef793b7a8244d1f23'
    assert m_44h_0h.chaincode.hex() == 'd665636fd64693411687f8d4deeb8382d14deb3d9937e72635e77af48c4da4e6'

    m_44h_0h_0h = deriveFromPath(seed, "m/44'/0'/0'")
    assert m_44h_0h_0h.privkey.hex() == '27b52d3d12ea694ced4d4ee5261d69fa06cfba73d318e734b586ef8d7738b9ee'
    assert m_44h_0h_0h.pubkey.hex() == '03fc371a6939557697a438cca5c81fc899d611d41f605d1b6d1a8096fd5e3e0343'
    assert m_44h_0h_0h.chaincode.hex() == 'fb106a1896e38ddc80b3d3b4fdaba9b003d1e6caa08c6cbbdc5d63fa6836b613'

    m_44h_0h_0h_0 = deriveFromPath(seed, "m/44'/0'/0'/0")
    assert m_44h_0h_0h_0.privkey.hex() == 'e519213b4099dc0a4f26d22ca0a09add7ebc7c6e3964d57f46617f8db522a97a'
    assert m_44h_0h_0h_0.pubkey.hex() == '0321bd38eb2f97c56762b82f22e9677d6aa205a73664b93aaf8ed087bd9fc26420'
    assert m_44h_0h_0h_0.chaincode.hex() == '29a2907541b35ab602c72d52c330184a2e7908060b98acca9b17ebfaea0135a8'

    m_44h_0h_0h_0_0 = deriveFromPath(seed, "m/44'/0'/0'/0/0")
    assert m_44h_0h_0h_0_0.privkey.hex() == '8d8f6c08e585a1804e9be03dd3f442e3dc7d8b7aad8f13f881490e18ef67b5ec'
    assert m_44h_0h_0h_0_0.pubkey.hex() == '025f4d47db93939b43261fc18d5b79e5eb0a46fd3a8feb279f57f8bd4c06a41acf'
    assert m_44h_0h_0h_0_0.chaincode.hex() == 'a3e1295ec9c664d73d77841b263d019306d914e431fdc84973cf53abaa0883cb'
    
    k = deriveFromPath(seed, "m/49'/0'/0'/0/0")
    assert k.privkey.hex() == '26e1061459e7961eeac018efa765339d785bd30de91f8fade64c639b275d74c4'
    assert k.pubkey.hex() == '021549dd72d89cbc844bb74ab6247239cf60d184cbfb0cfc4d024150a4985412fe'


def test_P2SH():
    """
    Tests derivation of Bitcoin P2SH address.
    This shows the complete process that works, then checks a function that does the same thing at the end.
    I know it's kinda goofy, but it should make debugging easier in the future if necessary.
    """
    seed = bytes.fromhex('65729d81d461591bac7384dea43dbd44438053cd1fdc113e0769c49c5fde025ba331eed2077497634e619948437d0448e769a86c0cbbecf01b13fd53540743b3')
    k = deriveFromPath(seed, "m/49'/0'/0'/0/0")
    assert k.privkey.hex() == '26e1061459e7961eeac018efa765339d785bd30de91f8fade64c639b275d74c4'
    assert k.pubkey.hex() == '021549dd72d89cbc844bb74ab6247239cf60d184cbfb0cfc4d024150a4985412fe'

    pkh = hashlib.sha256(k.pubkey).digest()
    assert pkh.hex() == '189a3015638daa02871973bf840b434aad92cb71775b65680acd266b81e85e3f'

    x = hashlib.new('ripemd160')
    x.update(pkh)
    assert x.digest().hex() == '2bf545ff88c159408f5ba759f99e78566763fe1a'

    s = b'\x00\x14' + x.digest() # script, \x00 is byte code for OP_0, \x14 for size of data to be pushed onto stack
    assert s.hex() == '00142bf545ff88c159408f5ba759f99e78566763fe1a'

    sh = hashlib.sha256(s).digest()
    assert sh.hex() == 'c2d24e021347966656ed4b0312f9b3a49498c257294bd75e9bc84ba8353deb9a'

    y = hashlib.new('ripemd160')
    y.update(sh)
    assert y.digest().hex() == '2d7193893e4143fc11bb69c7f004452198bdf6cd'

    serialization = b'\x05' + y.digest()
    assert serialization.hex() == '052d7193893e4143fc11bb69c7f004452198bdf6cd'

    checksum = hashlib.sha256(hashlib.sha256(serialization).digest()).digest()[:4]
    assert checksum.hex() == 'dcd3b30c'

    address_bytes = serialization + checksum
    assert address_bytes.hex() == '052d7193893e4143fc11bb69c7f004452198bdf6cddcd3b30c'

    address = base58.b58encode(address_bytes)
    assert address.decode('utf-8') == '35qJPbZX23wt3uuB9nz4pxhoouUfG28zxB'

    assert P2SH_addr_from_seed(seed, "m/49'/0'/0'/0/0") == '35qJPbZX23wt3uuB9nz4pxhoouUfG28zxB'


def P2SH_addr_from_seed(seed, dp):
    """
    Given a seed and a derivation path, create a P2SH address.
    These addresses start with a 3
    """
    # Check to make sure user is using appropriate derivation path.
    dpc = dp.split('/')
    if len(dpc) != 6:
        raise Exception(f"You didn't provide a derivation path of the form m/49'/0'/0'/0/0. You provided {dp}.")
    if dpc[0] != "m":
        raise Exception(f"Your derivation path {dp} does not start with an m.")
    if dpc[1] != "49'":
        raise Exception(f"Your derivation path {dp} does not start with a m/49'.")

    # Derive script hash
    k = deriveFromPath(seed, dp)
    pkh = hashlib.sha256(k.pubkey).digest() # public key hash
    rmd_pkh = hashlib.new('ripemd160')
    rmd_pkh.update(pkh)
    s = b'\x00\x14' + rmd_pkh.digest() # script, \x00 is byte code for OP_0, \x14 to push 20 bytes of data onto stack
    sh = hashlib.sha256(s).digest() # script hash, "putting the SH in P2SH!" (tm)

    # Derive address
    rmd_sh = hashlib.new('ripemd160')
    rmd_sh.update(sh)
    serialization = b'\x05' + rmd_sh.digest() # indicates a P2SH address
    checksum = hashlib.sha256(hashlib.sha256(serialization).digest()).digest()[:4] # so you don't send funds to an unredeemable address
    address_bytes = serialization + checksum
    address = base58.b58encode(address_bytes) # base58 for readability
    return address.decode('utf-8')


def P2PKH_addr_from_seed(seed, dp):
    """
    These addresses start with a 1.
    THIS HAS NOT BEEN TESTED!>!>!!!>>!!!!!:!LKJ!:LKJ:!LK!
    """
    # Check to make sure user is using appropriate derivation path.
    dpc = dp.split('/')
    if len(dpc) != 6:
        raise Exception(f"You didn't provide a derivation path of the form m/44'/0'/0'/0/0. You provided {dp}.")
    if dpc[0] != "m":
        raise Exception(f"Your derivation path {dp} does not start with an m.")
    if dpc[1] != "44'":
        raise Exception(f"Your derivation path {dp} does not start with a m/44'.")
    
    # Derive pubkey hash
    k = deriveFromPath(seed, dp)
    pkh = hashlib.sha256(k.pubkey).digest() # public key hash
    rmd_pkh = hashlib.new('ripemd160')
    rmd_pkh.update(pkh)

    # Derive address
    new_rmd_pkh = hashlib.new('ripemd160')
    new_rmd_pkh.update(pkh)
    serialization = b'\x00' + new_rmd_pkh.digest() # indicates a P2SH address, testnet uses '\x6f'
    checksum = hashlib.sha256(hashlib.sha256(serialization).digest()).digest()[:4] # so you don't send funds to an unredeemable address
    address_bytes = serialization + checksum
    address = base58.b58encode(address_bytes) # base58 for readability
    return address.decode('utf-8')


def P2PKH_addr_from_privkey(privkey):
    """
    These addresses start with a 1.
    """
    # Calculate pubkey
    k = Key()
    k.privkey = privkey
    k.pubkey = k.calcPubKey()

    # Derive pubkey hash
    pkh = hashlib.sha256(k.pubkey).digest() # public key hash
    rmd_pkh = hashlib.new('ripemd160')
    rmd_pkh.update(pkh)

    # Derive address
    new_rmd_pkh = hashlib.new('ripemd160')
    new_rmd_pkh.update(pkh)
    serialization = b'\x00' + new_rmd_pkh.digest() # indicates a P2SH address, testnet uses '\x6f'
    checksum = hashlib.sha256(hashlib.sha256(serialization).digest()).digest()[:4] # so you don't send funds to an unredeemable address
    address_bytes = serialization + checksum
    address = base58.b58encode(address_bytes) # base58 for readability
    return address.decode('utf-8')

def wif_to_pubkey(wif):
    """
    Not tested.
    https://en.bitcoin.it/wiki/Wallet_import_format
    """
    if wif[0] == '5':
        raise Exception("Corresponds to a compressed private key, not a public key.")
        
    base = base58.b58decode(wif)[:-5]
    checksum = base58.b58decode(wif)[-4:]
    if checksum != hashlib.sha256(hashlib.sha256(base).digest()).digest()[:4]:
        raise Exception("Invalid WIF")

    return base[1:]

def wif_to_privkey(wif):
    """
    https://en.bitcoin.it/wiki/Wallet_import_format
    """
    if wif[0] == 'K' or wif[0] == 'L':
        raise Exception("Corresponds to a compressed public key, not a private key.")

    base = base58.b58decode(wif)[:-4]
    checksum = base58.b58decode(wif)[-4:]
    if checksum != hashlib.sha256(hashlib.sha256(base).digest()).digest()[:4]:
        raise Exception("Invalid WIF")

    return base[1:]

def test_wif_to_privkey():
    assert wif_to_privkey('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ') == bytes.fromhex('0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D')

def test_P2PKH_addr_from_privkey():
    privkey = bytes.fromhex('60cf347dbc59d31c1358c8e5cf5e45b822ab85b79cb32a9f3d98184779a9efc2')
    assert P2PKH_addr_from_privkey(privkey) == '17JsmEygbbEUEpvt4PFtYaTeSqfb9ki1F1'

    privkey = bytes.fromhex('3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6')
    assert P2PKH_addr_from_privkey(privkey) == '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3'

    # From https://www.athenabitcoin.com/news/2018/4/9/how-to-use-a-paper-wallet, but not working.
    # wif = '5Jy7Pjm961LGR9HD7zW2nrMbXitrPose38nFhmJgaU91aibY8b5'
    # privkey = wif_to_privkey(wif)
    # assert P2PKH_addr_from_privkey(privkey) == '1HwWGwdzk5Ed7sMjpn9kadJQs5VEZ192wa'

def Bech32_addr_from_seed(seed, dp):
    """
    These addresses start with bc1
    """
    pass
    #   mnemonic = abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
    #   rootpriv = zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5
    #   rootpub  = zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF

    #   // Account 0, root = m/84'/0'/0'
    #   xpriv = zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE
    #   xpub  = zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs

    #   // Account 0, first receiving address = m/84'/0'/0'/0/0
    #   privkey = KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d
    #   pubkey  = 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c
    #   address = bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu

    #   // Account 0, second receiving address = m/84'/0'/0'/0/1
    #   privkey = Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy
    #   pubkey  = 03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77
    #   address = bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g

    #   // Account 0, first change address = m/84'/0'/0'/1/0
    #   privkey = KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF
    #   pubkey  = 03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6
    #   address = bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el

    # From trust wallet...
    # mnemo = mnemonic.Mnemonic("english")
    # seed = mnemo.to_seed("next dice bag ignore breeze lottery place arrow sign lizard rhythm barely")
    # bech32_addr = 'bc1qh84rcfsfq3mshkjd2s533ezw25llzjkj27mcu3'

def test_derivation_path():
    # https://www.oreilly.com/library/view/mastering-bitcoin/9781491902639/ch04.html
    mnemo = mnemonic.Mnemonic("english")
    phrase = 'army van defense carry jealous true garbage claim echo media make crunch'
    seed = mnemo.to_seed(phrase)
    assert P2PKH_addr_from_seed(seed,"m/44'/0'/0'/0/0") == '1HQ3rb7nyLPrjnuW85MUknPekwkn7poAUm'
    assert P2PKH_addr_from_seed(seed,"m/44'/0'/0'/0/1") == '1PJaTiHLZA2dWPFRHNBWogiiXhezuzqqqt'
    assert P2PKH_addr_from_seed(seed,"m/44'/0'/0'/0/2") == '142wFtNCL3cpCSju6rVQJYHWbgbs1c4oVa'
    assert P2PKH_addr_from_seed(seed,"m/44'/0'/0'/0/3") == '1PaCV3aA5abv7Bpac5QQhDBnzNFwfvvRhU'
    assert P2SH_addr_from_seed(seed,"m/49'/0'/0'/0/0") == '3FEQ7b7rMMRK3VmP778dUJCeQjBcQ4arXZ'
    assert P2SH_addr_from_seed(seed,"m/49'/0'/0'/0/1") == '3NxpyZsjsvkS54WcXksDsFpBKLvtDKcNMb'
    assert P2SH_addr_from_seed(seed,"m/49'/0'/0'/0/2") == '3P3oqY8EJRW47r54v98WmXKWsvhiGtdL61'
    assert P2SH_addr_from_seed(seed,"m/49'/0'/0'/0/3") == '3KqtmX47EUqKKqqSYtJdAawdFws5xEuUg8'

    # https://notatether.com/tutorials/full-guidecodeseed-phrase-the-process-of-deriving-bitcoin-addresses-from-it/
    seed = bytes.fromhex('65729d81d461591bac7384dea43dbd44438053cd1fdc113e0769c49c5fde025ba331eed2077497634e619948437d0448e769a86c0cbbecf01b13fd53540743b3')
    assert P2PKH_addr_from_seed(seed,"m/44'/0'/0'/0/0") == '1MbJqqvN8ZPYsUch45HdRAxKbH6bJeGfZi'
    assert P2PKH_addr_from_seed(seed,"m/44'/0'/0'/0/1") == '1GMpMNYwhb7Wvu8q1Zy52MtZUGWvLgCXak'
    assert P2PKH_addr_from_seed(seed,"m/44'/0'/0'/0/2") == '12fv5eg3kzBgZQy7ue2yYmC9xXohmKWGR3'

    # A random one that I made up
    mnemo = mnemonic.Mnemonic("english")
    phrase = 'frequent update bronze grass panther almost minor grunt item kiss icon suit'
    seed = mnemo.to_seed(phrase)
    assert P2SH_addr_from_seed(seed,"m/49'/0'/0'/0/0") == '37684qPyHz3HBPzst2WQqK7nuEWzn1NwgP'
    assert P2SH_addr_from_seed(seed,"m/49'/0'/0'/0/1") == '3NyZ8NRPXjCiFcvA6akwqmjVWP8LKnD9P4'

def run_tests():
    test_derivation()
    test_P2SH()
    test_P2PKH_addr_from_privkey()
    test_wif_to_privkey()
    test_derivation_path()


if __name__ == "__main__":

    run_tests()

    # Example
    seed_phrase = 'frequent update bronze grass panther almost minor grunt item kiss icon suit' # never use this for your own funds lolz
    seed = mnemonic.Mnemonic("english").to_seed(seed_phrase)
    print(P2PKH_addr_from_seed(seed,"m/44'/0'/0'/0/0"))
    print(P2SH_addr_from_seed(seed,"m/49'/0'/0'/0/0"))