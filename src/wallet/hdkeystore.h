// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_HDKEYSTORE_H
#define BITCOIN_WALLET_HDKEYSTORE_H

#include "keystore.h"
#include "wallet/crypter.h"
#include "serialize.h"
#include "pubkey.h"

typedef uint256 HDChainID;

/** hdpublic key for a persistant store. */
class CHDPubKey
{
public:
    static const int CURRENT_VERSION=1;
    int nVersion;

    CPubKey pubkey;
    unsigned int nChild;
    HDChainID chainID; //hash of the chains master pubkey
    std::string keypath; //example: m/44'/0'/0'/0/1
    bool internal;

    CHDPubKey()
    {
        SetNull();
    }

    bool IsValid()
    {
        return pubkey.IsValid();
    }

    void SetNull()
    {
        nVersion = CHDPubKey::CURRENT_VERSION;
        chainID.SetNull();
        keypath.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;

        READWRITE(pubkey);
        READWRITE(nChild);
        READWRITE(chainID);
        READWRITE(keypath);
        READWRITE(internal);
    }
};

/** class for representing a hd chain of keys. */
class CHDChain
{
public:
    static const int CURRENT_VERSION=1;
    int nVersion;
    bool usePubCKD;
    int64_t nCreateTime; // 0 means unknown

    HDChainID chainID; //hash of the masterpubkey
    std::string keypathTemplate; //example "m'/44'/0'/0'/c"
    CExtPubKey externalPubKey;
    CExtPubKey internalPubKey; // pubkey.IsValid() == false means only use external chain

    CHDChain()
    {
        SetNull();
    }

    CHDChain(int64_t nCreateTime_)
    {
        SetNull();
        nCreateTime = nCreateTime_;
    }

    bool IsValid()
    {
        if (usePubCKD && !externalPubKey.pubkey.IsValid())
            return false;
        return (keypathTemplate.size() > 0);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(this->nVersion);
        nVersion = this->nVersion;

        READWRITE(nCreateTime);
        READWRITE(chainID);
        READWRITE(keypathTemplate);
        READWRITE(usePubCKD);
        if (usePubCKD)
        {
            READWRITE(externalPubKey);
            READWRITE(internalPubKey);
        }
    }

    void SetNull()
    {
        nVersion = CHDChain::CURRENT_VERSION;
        nCreateTime = 0;
        chainID.SetNull();
        keypathTemplate.clear();
        usePubCKD = false;
    }
};

class CHDKeyStore : public CCryptoKeyStore
{
protected:
    std::map<HDChainID, CKeyingMaterial > mapHDMasterSeeds; //master seeds are stored outside of CHDChain (mind crypting)
    std::map<HDChainID, std::vector<unsigned char> > mapHDCryptedMasterSeeds;
    std::map<CKeyID, CHDPubKey> mapHDPubKeys; //all hd pubkeys of all chains
    std::map<HDChainID, CHDChain> mapChains; //all available chains

    //!private key derivition of a ext priv key
    bool PrivKeyDer(const std::string chainPath, const HDChainID& chainID, CExtKey& extKeyOut) const;

    //!derive key from a CHDPubKey object
    bool DeriveKey(const CHDPubKey hdPubKey, CKey& keyOut) const;

public:
    //!add a master seed with a given pubkeyhash (memory only)
    virtual bool AddMasterSeed(const HDChainID& chainID, const CKeyingMaterial& masterSeed);

    //!add a crypted master seed with a given pubkeyhash (memory only)
    virtual bool AddCryptedMasterSeed(const HDChainID& chainID, const std::vector<unsigned char>& vchCryptedSecret);

    //!encrypt existing uncrypted seeds and remove unencrypted data
    virtual bool EncryptSeeds();

    //!export the master seed from a given chain id (hash of the master pub key)
    virtual bool GetMasterSeed(const HDChainID& chainID, CKeyingMaterial& seedOut) const;

    //!get the encrypted master seed of a giveb chain id
    virtual bool GetCryptedMasterSeed(const HDChainID& chainID, std::vector<unsigned char>& vchCryptedSecret) const;

    //!writes all available chain ids to a vector
    virtual bool GetAvailableChainIDs(std::vector<HDChainID>& chainIDs);

    //!add a CHDPubKey object to the keystore (memory only)
    bool LoadHDPubKey(const CHDPubKey &pubkey);

    //!add a new chain to the keystore (memory only)
    bool AddChain(const CHDChain& chain);

    //!writes a chain defined by given chainId to chainOut, returns false if not found
    bool GetChain(const HDChainID chainID, CHDChain& chainOut) const;

    //!Derives a CHDPubKey object in a given chain defined by chainId from the existing external or internal chain root pub key
    bool DeriveHDPubKeyAtIndex(const HDChainID chainID, CHDPubKey& hdPubKeyOut, unsigned int nIndex, bool internal) const;

    /**
     * Get next available index for a child key in chain defined by given chain id
     * @return next available index
     * @warning This will "fill gaps". If you have m/0/0, m/0/1, m/0/2, m/0/100 it will return 3 (m/0/3)
     */
    unsigned int GetNextChildIndex(const HDChainID& chainID, bool internal);

    //!check if a wallet has a certain key
    bool HaveKey(const CKeyID &address) const;

    //!get a key with given keyid for signing, etc. (private key operation)
    bool GetKey(const CKeyID &address, CKey &keyOut) const;

    //!get a pubkey with given keyid for verifiying, etc.
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const;
};
#endif // BITCOIN_WALLET_HDKEYSTORE_H
