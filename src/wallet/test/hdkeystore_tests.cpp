// Copyright (c) 2012-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "base58.h"

#include <set>
#include <stdint.h>
#include <utility>
#include <vector>

#include "test/test_bitcoin.h"

#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>

extern CWallet* pwalletMain;

BOOST_FIXTURE_TEST_SUITE(hdkeystore_tests, TestingSetup)


BOOST_AUTO_TEST_CASE(hdkeystore_tests)
{
    LOCK(pwalletMain->cs_wallet);
    
    CKey key;
    key.MakeNewKey(true);

    CHDChain chain;
    chain.keypathTemplate = "m/c'";

    std::vector<unsigned char> vSeed = ParseHex("9886e45b8435b488a4cb753121db41a07f66a6a73e0a705ce24cee3a3bce87db");

    CKeyingMaterial seed = CKeyingMaterial(32);
    seed.assign(vSeed.front(), vSeed.back());

    CExtKey masterKey;
    masterKey.SetMaster(&seed[0], seed.size());
    CBitcoinExtKey masterXPriv;
    masterXPriv.SetKey(masterKey);
    BOOST_CHECK(masterXPriv.ToString() == "xprv9s21ZrQH143K3p7CoBzQ9XPGDfaK8YHfuy11V3tGCG715SX1FYhZRP4rqCDKryZDiFtcvfr9A9aQCSioUTScA6reJktbLqEW6soRZfyZqU9");


    CExtPubKey masterPubKey = masterKey.Neuter();
    chain.chainID = masterPubKey.pubkey.GetHash();

    pwalletMain->AddChain(chain);
    pwalletMain->AddMasterSeed(chain.chainID, seed);

    CHDPubKey hdpubkey;
    pwalletMain->DeriveHDPubKeyAtIndex(chain.chainID, hdpubkey, 0, false);
    BOOST_CHECK(pwalletMain->GetNextChildIndex(chain.chainID, false) == 0);
    pwalletMain->LoadHDPubKey(hdpubkey);
    BOOST_CHECK(pwalletMain->GetNextChildIndex(chain.chainID, false) == 1);

    std::string test = CBitcoinAddress(hdpubkey.pubkey.GetID()).ToString();
    BOOST_CHECK(CBitcoinAddress(hdpubkey.pubkey.GetID()).ToString() == "1AFW8Aq7jXmtqLHjicMtov56FRBeYqSHj7");

    pwalletMain->DeriveHDPubKeyAtIndex(chain.chainID, hdpubkey, pwalletMain->GetNextChildIndex(chain.chainID, false), false);
    pwalletMain->LoadHDPubKey(hdpubkey);

    BOOST_CHECK(CBitcoinAddress(hdpubkey.pubkey.GetID()).ToString() == "1JCWakvgoCcKHLydjrbFqeAM1vyF36sRe8");

    pwalletMain->EncryptSeeds();
    BOOST_CHECK(pwalletMain->HaveKey(hdpubkey.pubkey.GetID()) == true);

    CKey keyTest;
    pwalletMain->GetKey(hdpubkey.pubkey.GetID(), keyTest);

    BOOST_CHECK(CBitcoinSecret(keyTest).ToString() == "L3FttmGb7kM6GYUxpR3d4LSVRLzXUfTUpa5wezXH17iqUEfP2MD4");
}

BOOST_AUTO_TEST_SUITE_END()
