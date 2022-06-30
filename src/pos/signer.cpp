// Copyright (c) 2014-2021 The Reddcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/signer.h>

#include <chainparams.h>

typedef std::vector<unsigned char> valtype;

bool SignBlock(CBlock& block, const CKeyStore& keystore)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    const CTxOut& txout = block.IsProofOfStake()? block.vtx[1]->vout[1] : block.vtx[0]->vout[0];

    if (!Solver(txout.scriptPubKey, whichType, vSolutions))
        return false;
    if (whichType == TX_PUBKEY)
    {
        // Sign
        const valtype& vchPubKey = vSolutions[0];
        CKey key;
        if (!keystore.GetKey(CKeyID(Hash160(vchPubKey)), key))
            return false;
        if (key.GetPubKey() != CPubKey(vchPubKey))
            return false;
        return key.Sign(block.GetHash(), block.vchBlockSig);
    }
    return false;
}

// POSV : check block signature
bool CheckBlockSignature(const CBlock& block)
{
    if (block.IsProofOfWork())
        return block.vchBlockSig.empty();

    if (block.GetHash() == Params().GetConsensus().hashGenesisBlock)
        return block.vchBlockSig.empty();

    std::vector<valtype> vSolutions;
    txnouttype whichType;
    const CTxOut& txout = block.vtx[1]->vout[1];

    if (!Solver(txout.scriptPubKey, whichType, vSolutions)){
        printf("CheckBlockSignature() Solver()");
        return false;
    }
    if (whichType == TX_PUBKEY)
    {
        const valtype& vchPubKey = vSolutions[0];
        CPubKey key(vchPubKey);
        if (block.vchBlockSig.empty()){
            printf("block.vchBlockSig.empty()");
            return false;}
        return key.Verify(block.GetHash(), block.vchBlockSig);
    }
    printf("CheckBlockSignature() END");
    return false;
}
