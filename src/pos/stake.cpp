// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/stake.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <fs.h>
#include <index/txindex.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <keystore.h>
#include <validation.h>
#include <key_io.h>
#include <miner.h>
#include <outputtype.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <pos/kernel.h>
#include <pos/signer.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <index/txindex.h>
#include <txmempool.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>
#include <wallet/wallet.h>
#include <txdb.h>

#include <univalue.h>

#include <algorithm>
#include <assert.h>
#include <optional>

bool GetStakeWeight(const CWallet* pwallet, uint64_t& nAverageWeight, uint64_t & nTotalWeight, const Consensus::Params& consensusParams)
{
      // Choose coins to use
      LOCK(pwallet->cs_wallet);
      CAmount nBalance = pwallet->GetBalance();
      CAmount nReserveBalance = 0;
      if (gArgs.IsArgSet("-reservebalance") && !ParseMoney(gArgs.GetArg("-reservebalance", ""), nReserveBalance))
          return error("CreateCoinStake : invalid reserve balance amount");
      if (nBalance <= nReserveBalance)
          return false;

      std::vector<CTransactionRef> vwtxPrev;
      std::set<CInputCoin> setCoins;

      CAmount nValueIn = 0;

      std::vector<COutput> vAvailableCoins;
      CCoinControl temp;
      bool bnb_used;
      CoinSelectionParams coin_selection_params;
      pwallet->AvailableCoins(vAvailableCoins, true, &temp);
      if (!pwallet->SelectCoins(vAvailableCoins, nBalance - nReserveBalance, setCoins, nValueIn, temp, coin_selection_params, bnb_used))
	  return false;
      if (setCoins.empty())
	  return false;

      nAverageWeight = nTotalWeight = 0;
      uint64_t nWeightCount = 0;

      for (const auto& pcoin : setCoins)
      {
	  CDiskTxPos postx;
	  if (!g_txindex->FindTxPosition(pcoin.outpoint.hash, postx))
	      continue;

	  // Read block header
	  CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
	  CBlockHeader header;
	  CTransactionRef txRef;
	  try {
	      file >> header;
	      fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
	      file >> txRef;
	  } catch (std::exception &e) {
	      return error("%s() : deserialize or I/O error in GetStakeWeight()", __PRETTY_FUNCTION__);
	  }

	  CMutableTransaction tx(*txRef);

	  // Deal with transaction timestmap
	  unsigned int nTimeTx = tx.nTime ? tx.nTime : header.GetBlockTime();

	  int64_t nTimeWeight = GetCoinAgeWeight((int64_t)nTimeTx, (int64_t)GetTime());
	  arith_uint256 bnCoinDayWeight = arith_uint256(pcoin.txout.nValue) * nTimeWeight / COIN / (24 * 60 * 60);

	  // Weight is greater than zero
	  if (nTimeWeight > 0)
	  {
	      nTotalWeight += bnCoinDayWeight.GetLow64();
	      nWeightCount++;
	  }

      }

  if (nWeightCount > 0)
      nAverageWeight = nTotalWeight / nWeightCount;

  return true;
}


// create coin stake transaction
typedef std::vector<unsigned char> valtype;
bool CreateCoinStake(const CWallet* pwallet, unsigned int nBits, int64_t nSearchInterval, CMutableTransaction& txNew, const Consensus::Params& consensusParams, const CAmount& nFees)
{
    // The following split & combine thresholds are important to security
    // Should not be adjusted if you don't understand the consequences
    static unsigned int nStakeSplitAge = (60 * 60 * 24 * 90);
    int64_t nCombineThreshold = 20 * COIN; //UpdateMe

    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    // Transaction index is required to get to block header
    if (!g_txindex)
        return error("CreateCoinStake : transaction index unavailable");

    LOCK2(cs_main, pwallet->cs_wallet);
    txNew.vin.clear();
    txNew.vout.clear();

    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));

    // Choose coins to use
    CAmount nBalance = pwallet->GetBalance();
    CAmount nReserveBalance = 0;
    if (gArgs.IsArgSet("-reservebalance") && !ParseMoney(gArgs.GetArg("-reservebalance", ""), nReserveBalance))
        return error("CreateCoinStake : invalid reserve balance amount");
    if (nBalance <= nReserveBalance)
        return false;
    std::set<CInputCoin> setCoins;
    std::vector<CTransactionRef> vwtxPrev;
    CAmount nValueIn = 0;
    std::vector<COutput> vAvailableCoins;
    CCoinControl temp;
    bool bnb_used;
    CoinSelectionParams coin_selection_params;
    pwallet->AvailableCoins(vAvailableCoins, true, &temp);
    if (!pwallet->SelectCoins(vAvailableCoins, nBalance - nReserveBalance, setCoins, nValueIn, temp, coin_selection_params, bnb_used))
        return false;
    if (setCoins.empty())
        return false;
    CAmount nCredit = 0;
    CScript scriptPubKeyKernel;
    for (const auto& pcoin : setCoins)
    {

        if (!EnableStaking()) {
            return false;
        }
        CDiskTxPos postx;
        if (!g_txindex->FindTxPosition(pcoin.outpoint.hash, postx))
            continue;

        // Read block header
        CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
        CBlockHeader header;
        CTransactionRef tx;
        try {
            file >> header;
            fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
            file >> tx;
        } catch (std::exception &e) {
            return error("%s() : deserialize or I/O error in CreateCoinStake()", __PRETTY_FUNCTION__);
        }

        static int nMaxStakeSearchInterval = 60;
        if (header.GetBlockTime() + consensusParams.nStakeMinAge > txNew.nTime - nMaxStakeSearchInterval)
            continue; // only count coins meeting min age requirement

        bool fKernelFound = false;
        for (unsigned int n=0; n<std::min(nSearchInterval,(int64_t)nMaxStakeSearchInterval) && !fKernelFound; n++)
        {
            // Search backward in time from the given txNew timestamp
            // Search nSearchInterval seconds back up to nMaxStakeSearchInterval
            uint256 hashProofOfStake = uint256();
            COutPoint prevoutStake = pcoin.outpoint;
            bool foundStake = CheckStakeKernelHash(nBits, header, prevoutStake.n, tx, prevoutStake, txNew.nTime - n, hashProofOfStake, gArgs.GetBoolArg("-printstakemodifier", false));
            if (foundStake)
            {
                // Found a kernel
                if (gArgs.GetBoolArg("-printcoinstake", false))
                    LogPrintf("CreateCoinStake : kernel found\n");
                std::vector<valtype> vSolutions;
                txnouttype whichType;
                CScript scriptPubKeyOut;
                scriptPubKeyKernel = pcoin.txout.scriptPubKey;
                if (!Solver(scriptPubKeyKernel, whichType, vSolutions))
                {
                    if (gArgs.GetBoolArg("-printcoinstake", false))
                        LogPrintf("CreateCoinStake : failed to parse kernel type=%d\n", whichType);
                    break;
                }
                if (gArgs.GetBoolArg("-printcoinstake", false))
                    LogPrintf("CreateCoinStake : parsed kernel type=%d\n", whichType);
                if (whichType != TX_PUBKEY && whichType != TX_PUBKEYHASH && whichType != TX_WITNESS_V0_KEYHASH) {
                    if (gArgs.GetBoolArg("-printcoinstake", false))
                        LogPrintf("CreateCoinStake : no support for kernel type=%s\n", GetTxnOutputType(whichType));
                    break;
                }
                if (whichType == TX_PUBKEYHASH || whichType == TX_WITNESS_V0_KEYHASH) // pay to address type or witness keyhash
                {
                    // convert to pay to public key type
                    CKey key;
                    const CKeyStore& keystore = *pwallet;
                    if (!keystore.GetKey(CKeyID(uint160(vSolutions[0])), key)) {
                        if (gArgs.GetBoolArg("-printcoinstake", false))
                            LogPrintf("CreateCoinStake : failed to get key for kernel type=%s\n", GetTxnOutputType(whichType));
                        break;
                    }
                    scriptPubKeyOut << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;
                }
                else
                    scriptPubKeyOut = scriptPubKeyKernel;

                txNew.nTime -= n;
                txNew.vin.push_back(CTxIn(pcoin.outpoint.hash, pcoin.outpoint.n));
                nCredit += pcoin.txout.nValue;
                vwtxPrev.push_back(tx);
                txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));
                if (header.GetBlockTime() + nStakeSplitAge > txNew.nTime)
                    txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));
                fKernelFound = true;
                break;
            }
        }
        if (fKernelFound)
            break; // if kernel is found stop searching
    }
    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
        return false;
    for (const auto& pcoin : setCoins)
    {
        CDiskTxPos postx;
        if (!g_txindex->FindTxPosition(pcoin.outpoint.hash, postx))
            continue;

        // Read block header
        CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
        CBlockHeader header;
        CTransactionRef tx;
        try {
            file >> header;
            fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
            file >> tx;
        } catch (std::exception &e) {
            return error("%s() : deserialize or I/O error in CreateCoinStake()", __PRETTY_FUNCTION__);
        }


        // Attempt to add more inputs
        // Only add coins of the same key/address as kernel
        if (txNew.vout.size() == 3 && ((pcoin.txout.scriptPubKey == scriptPubKeyKernel || pcoin.txout.scriptPubKey == txNew.vout[1].scriptPubKey))
            && pcoin.outpoint.hash != txNew.vin[0].prevout.hash)
        {
            // Stop adding more inputs if already too many inputs
            if (txNew.vin.size() >= 100)
                break;
            // Stop adding more inputs if value is already pretty significant
            if (nCredit > nCombineThreshold)
                break;
            // Stop adding inputs if reached reserve limit
            if (nCredit + pcoin.txout.nValue > nBalance - nReserveBalance)
                break;
            // Do not add additional significant input
            if (pcoin.txout.nValue > nCombineThreshold)
                continue;
            // Do not add input that is still too young
            if (tx->nTime + consensusParams.nStakeMaxAge > txNew.nTime)
                continue;
            txNew.vin.push_back(CTxIn(pcoin.outpoint.hash, pcoin.outpoint.n));
            nCredit += pcoin.txout.nValue;
            vwtxPrev.push_back(tx);
        }
    }

    // Add Dev fund output
    if(CBlockHeader::CURRENT_VERSION >= 5){
    txNew.vout.push_back(CTxOut(0, consensusParams.devScript.front()));
    }
    CAmount nEndCredit = 0;
    CAmount nDevCredit = 0;

    // Calculate coin age reward
    {
        uint64_t nCoinAge = GetCoinAge((const CTransaction)txNew);
        
        if (!nCoinAge)
            return error("CreateCoinStake : failed to calculate coin age");

        CAmount nReward = 0;
        if(CTransaction::CURRENT_VERSION >= 2){
        double fInflationAdjustment = GetInflationAdjustment(chainActive.Tip());
        nReward = GetProofOfStakeReward(nCoinAge, nFees, fInflationAdjustment);  
        }else{
        nReward = GetProofOfStakeReward(nCoinAge, nFees); 
        }

        // Refuse to create mint that has reward less than fees
        if (nReward <= 0) {
          return false;
        }
        
        if(CTransaction::CURRENT_VERSION >= 2){  
        // Split fund output 92-8%
        nEndCredit += nReward * 0.92;
        nDevCredit += nReward - nEndCredit;
        }else{
        nEndCredit += nReward;
        nDevCredit += 0;
        }
        nCredit += nEndCredit;
    }

    if(gArgs.GetBoolArg("-printcoinstake", false))
        LogPrintf("%s: nCredit=%s nEndCredit=%s nDevCredit=%s\n",__func__, nCredit, nEndCredit, nDevCredit);

    CAmount nMinFee = 0;
    CAmount nMinFeeBase = MIN_TX_FEE;

    while(true)
    {
       

        // Set output amount
        if (txNew.vout.size() == 4)
        {
            txNew.vout[1].nValue = (nCredit / 2 / CENT) * CENT;
            txNew.vout[2].nValue = nCredit - txNew.vout[1].nValue;
            txNew.vout[3].nValue = nDevCredit;
        }
        else if (txNew.vout.size() == 3)
        {
            txNew.vout[1].nValue = (nCredit / 2 / CENT) * CENT;
            txNew.vout[2].nValue = nCredit - txNew.vout[1].nValue;
        }else{
            txNew.vout[1].nValue = nCredit;
        }
        

        // Sign
        int nIn = 0;
        for (const auto& pcoin : vwtxPrev)
        {
            if (!SignSignature(*pwallet, *pcoin, txNew, nIn++, SIGHASH_ALL))
                return error("CreateCoinStake : failed to sign coinstake");
        }

        // Limit size
        unsigned int nBytes = ::GetSerializeSize(txNew, PROTOCOL_VERSION);
        if (nBytes >= 1000000/5)
            return error("CreateCoinStake : exceeded coinstake size limit");

        // Check enough fee is paid
        if (nMinFee < GetMinFee(CTransaction(txNew)) - nMinFeeBase)
        {
            nMinFee = GetMinFee(CTransaction(txNew)) - nMinFeeBase;
            continue; // try signing again
        }
        else
        {
            if (gArgs.GetBoolArg("-printcoinstake", false))
                LogPrintf("CreateCoinStake : fee for coinstake %s\n", FormatMoney(nMinFee).c_str());
            break;
        }
    }

    // Successfully generated coinstake
    return true;
}
