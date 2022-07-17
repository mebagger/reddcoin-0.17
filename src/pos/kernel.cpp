// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2014 The Reddcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos/kernel.h>
#include <chainparams.h>
#include <util.h>
#include <utiltime.h>
#include <logging.h>
#include <validation.h>
#include <streams.h>
#include <timedata.h>
#include <txdb.h>
#include <index/txindex.h>
#include <consensus/validation.h>
#include <pos/modifiercache.h>
#include <random.h>
#include <script/interpreter.h>
#include <rpc/blockchain.h>

#include <arith_uint256.h>
#include <uint256.h>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>

using namespace std;

typedef map<int, uint64_t> MapModifierCheckpoints;

// This leads to a modifier selection interval of 27489 seconds,
// which is roughly 7 hours 38 minutes, just a bit shorter than
// the minimum stake age of 8 hours.
unsigned int nModifierInterval = 13 * 60;

// FIXME
// Hard checkpoints of stake modifiers to ensure they are deterministic
static map<int, uint64_t> mapStakeModifierCheckpoints =
    boost::assign::map_list_of(0, 0xfd11f4e7)(1000, 0x71168906)(2000, 0x4f2ef99d);

// Hard checkpoints of stake modifiers to ensure they are deterministic (testNet)
static map<int, uint64_t> mapStakeModifierCheckpointsTestNet =
    boost::assign::map_list_of
    (0, 0x0e00670b)
    ;
    //boost::assign::map_list_of(0, 0xfd11f4e7);

// linear coin-aging function
int64_t GetCoinAgeWeightLinear(int64_t nIntervalBeginning, int64_t nIntervalEnd)
{
    // Kernel hash weight starts from 0 at the min age
    // this change increases active coins participating the hash and helps
    // to secure the network when proof-of-stake difficulty is low
    return max((int64_t)0, min(nIntervalEnd - nIntervalBeginning - Params().GetConsensus().nStakeMinAge, (int64_t)Params().GetConsensus().nStakeMaxAge));
}

/* PoSV: Coin-aging function
 * =================================================
 * WARNING
 * =================================================
 * The parameters used in this function are the
 * solutions to a set of intricate mathematical
 * equations chosen specifically to incentivise
 * owners of Reddcoin to participate in minting.
 * These parameters are also affected by the values
 * assigned to other variables such as expected
 * block confirmation time.
 * If you are merely forking the source code of
 * Reddcoin, it's highly UNLIKELY that this set of
 * parameters work for your purpose. In particular,
 * if you have tweaked the values of other variables,
 * this set of parameters are certainly no longer
 * valid. You should revert back to the linear
 * function above or the security of your network
 * will be significantly impaired.
 * In short, do not use or change this function
 * unless you have spoken to the author.
 * =================================================
 * DO NOT USE OR CHANGE UNLESS YOU ABSOLUTELY
 * KNOW WHAT YOU ARE DOING.
 * =================================================
 */
int64_t GetCoinAgeWeight(int64_t nIntervalBeginning, int64_t nIntervalEnd)
{
    if (nIntervalBeginning <= 0) {
        LogPrintf("WARNING *** GetCoinAgeWeight: nIntervalBeginning (%d) <= 0\n", nIntervalBeginning);
        return 0;
    }

    int64_t nSeconds = std::max((int64_t)0, nIntervalEnd - nIntervalBeginning - Params().GetConsensus().nStakeMinAge);
    double days = double(nSeconds) / (24 * 60 * 60);
    double weight = 0;

    if (days <= 7) {
        weight = -0.00408163 * pow(days, 3) + 0.05714286 * pow(days, 2) + days;
    } else {
        weight = 8.4 * log(days) - 7.94564525;
    }

    return std::min((int64_t)(weight * 24 * 60 * 60), (int64_t)Params().GetConsensus().nStakeMaxAge);
}

// Get the last stake modifier and its generation time from a given block
static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime)
{
    if (!pindex)
        return error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier())
        return error("GetLastStakeModifier: no generation at genesis block");
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

// Get selection interval section (in seconds)
static int64_t GetStakeModifierSelectionIntervalSection(int nSection)
{
    assert(nSection >= 0 && nSection < 64);
    return (nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
}

// Get stake modifier selection interval (in seconds)
static int64_t GetStakeModifierSelectionInterval()
{
    int64_t nSelectionInterval = 0;
    for (int nSection = 0; nSection < 64; nSection++)
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection);

    if (gArgs.GetBoolArg("-debug", false))
        LogPrintf("GetStakeModifierSelectionInterval : %d\n", nSelectionInterval);

    return nSelectionInterval;
}

// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static bool SelectBlockFromCandidates(
    vector<pair<int64_t, uint256> >& vSortedByTimestamp, 
    map<uint256, const CBlockIndex*>& mapSelectedBlocks, 
    int64_t nSelectionIntervalStop, uint64_t nStakeModifierPrev, 
    const CBlockIndex** pindexSelected)
{
    bool fSelected = false;
    arith_uint256 hashBest = 0;
    *pindexSelected = (const CBlockIndex*)0;
    for (const auto& item : vSortedByTimestamp)
    {
        if (!mapBlockIndex.count(item.second))
            return error("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString());
        const CBlockIndex* pindex = mapBlockIndex[item.second];
        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;
        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;
        // compute the selection hash by hashing its proof-hash and the
        // previous proof-of-stake modifier
        CDataStream ss(SER_GETHASH, 0);
        ss << pindex->hashProof << nStakeModifierPrev;
        arith_uint256 hashSelection = UintToArith256(Hash(ss.begin(), ss.end()));
        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;
        if (fSelected && hashSelection < hashBest) {
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*)pindex;
        } else if (!fSelected) {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*)pindex;
        }
    }
    if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrintf("SelectBlockFromCandidates: selection hash=%s\n", hashBest.ToString());
    return fSelected;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier)
{
    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    if (!pindexPrev) {
        fGeneratedStakeModifier = true;
        return true; // genesis block's modifier is 0
    }
    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64_t nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime))
        return error("ComputeNextStakeModifier: unable to get last modifier");

    if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrintf("ComputeNextStakeModifier: prev modifier=0x%016x time=%s height=%d\n", nStakeModifier, FormatISO8601DateTime( nModifierTime), pindexPrev->nHeight);

    if (nModifierTime / nModifierInterval >= pindexPrev->GetBlockTime() / nModifierInterval)
        return true;

    // Sort candidate blocks by timestamp
    std::vector<std::pair<int64_t, uint256>> vSortedByTimestamp;
    vSortedByTimestamp.reserve(64 * nModifierInterval / Params().GetConsensus().nPowTargetSpacing);
    int64_t nSelectionInterval = GetStakeModifierSelectionInterval();
    int64_t nSelectionIntervalStart = (pindexPrev->GetBlockTime() / nModifierInterval) * nModifierInterval - nSelectionInterval;
    const CBlockIndex* pindex = pindexPrev;
    while (pindex && pindex->GetBlockTime() >= nSelectionIntervalStart) {
        vSortedByTimestamp.push_back(make_pair(pindex->GetBlockTime(), pindex->GetBlockHash()));
        pindex = pindex->pprev;
        if (gArgs.GetBoolArg("-printstakemodifier", false)){
        LogPrintf("ComputeNextStakeModifier: prev EpochTime=%lu time=%s height=%d hash=%s\n", pindex->GetBlockTime(), FormatISO8601DateTime(pindex->GetBlockTime()), pindex->nHeight, pindex->GetBlockHash().ToString());
        }
    }
    int nHeightFirstCandidate = pindex ? (pindex->nHeight + 1) : 0;
    std::reverse(vSortedByTimestamp.begin(), vSortedByTimestamp.end());
    std::sort(vSortedByTimestamp.begin(), vSortedByTimestamp.end(), [] (const std::pair<int64_t, uint256> &a, const std::pair<int64_t, uint256> &b)
    {
        if (a.first != b.first)
            return a.first < b.first;
        // Timestamp equals - compare block hashes
        const uint32_t *pa = a.second.GetDataPtr();
        const uint32_t *pb = b.second.GetDataPtr();
        int cnt = 256 / 32;
        do {
            --cnt;
            if (pa[cnt] != pb[cnt])
                return pa[cnt] < pb[cnt];
        } while(cnt);
            return false; // Elements are equal
    });

    // Select 64 blocks from candidate blocks to generate stake modifier
    uint64_t nStakeModifierNew = 0;
    int64_t nSelectionIntervalStop = nSelectionIntervalStart;
    std::map<uint256, const CBlockIndex*> mapSelectedBlocks;
    for (int nRound = 0; nRound < std::min(64, (int)vSortedByTimestamp.size()); nRound++) {
        // add an interval section to the current selection round
        nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound);
        // select a block from the candidates of current round
        if (!SelectBlockFromCandidates(vSortedByTimestamp, mapSelectedBlocks, nSelectionIntervalStop, nStakeModifier, &pindex))
            return error("ComputeNextStakeModifier: unable to select block at round %d", nRound);
        // write the entropy bit of the selected block
        nStakeModifierNew |= (((uint64_t)pindex->GetStakeEntropyBit()) << nRound);
        // add the selected block from candidates to selected list
        mapSelectedBlocks.insert(std::make_pair(pindex->GetBlockHash(), pindex));
        if (gArgs.GetBoolArg("-printstakemodifier", false))
            LogPrintf("ComputeNextStakeModifier: selected round %d stop=%s height=%d hash=%s bit=%d\n", nRound, FormatISO8601DateTime( nSelectionIntervalStop), pindex->nHeight,pindex->GetBlockHash().ToString(), pindex->GetStakeEntropyBit());
    }

    // Print selection map for visualization of the selected blocks
    if ( gArgs.GetBoolArg("-printstakemodifier", false)) {
        string strSelectionMap = "";
        // '-' indicates proof-of-work blocks not selected
        strSelectionMap.insert(0, pindexPrev->nHeight - nHeightFirstCandidate + 1, '-');
        pindex = pindexPrev;
        while (pindex && pindex->nHeight >= nHeightFirstCandidate) {
            // '=' indicates proof-of-stake blocks not selected
            if (pindex->IsProofOfStake())
                strSelectionMap.replace(pindex->nHeight - nHeightFirstCandidate, 1, "=");
            pindex = pindex->pprev;
        }
        for (const auto& item : mapSelectedBlocks)
        {
            // 'S' indicates selected proof-of-stake blocks
            // 'W' indicates selected proof-of-work blocks
            strSelectionMap.replace(item.second->nHeight - nHeightFirstCandidate, 1, item.second->IsProofOfStake() ? "S" : "W");
        }
        LogPrintf("ComputeNextStakeModifier: selection height [%d, %d] map %s\n", nHeightFirstCandidate, pindexPrev->nHeight, strSelectionMap.c_str());
    }

    if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrintf("ComputeNextStakeModifier: new modifier=0x%016x time=%s nHeight=%d\n", nStakeModifierNew,
                  FormatISO8601DateTime(pindexPrev->GetBlockTime()), pindexPrev->nHeight + 1);

    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
static bool GetKernelStakeModifier(uint256 hashBlockFrom, uint64_t& nStakeModifier, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake)
{
    nStakeModifier = 0;
    const CBlockIndex* pindexFrom = LookupBlockIndex(hashBlockFrom);
    if (!pindexFrom)
        return error("GetKernelStakeModifier() : block not indexed");
    nStakeModifierHeight = pindexFrom->nHeight;
    nStakeModifierTime = pindexFrom->GetBlockTime();
    int64_t nStakeModifierSelectionInterval = GetStakeModifierSelectionInterval();


        // Check the cache first
    uint64_t nCachedModifier;
    cachedModifier entry { nStakeModifierTime, nStakeModifierHeight };
    if (cacheCheck(entry, nCachedModifier)) {
        nStakeModifier = nCachedModifier;
        if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrintf("%s: nStakeModifier=0x%08x cache hit!\n", __func__, nStakeModifier);
        return true;
    }

    const CBlockIndex* pindex = pindexFrom;
    // loop to find the stake modifier later by a selection interval
    while (nStakeModifierTime < pindexFrom->GetBlockTime() + nStakeModifierSelectionInterval) {
        if (!chainActive.Next(pindex)) { // reached best block; may happen if node is behind on block chain
            if (fPrintProofOfStake || (pindex->GetBlockTime() + Params().GetConsensus().nStakeMinAge - nStakeModifierSelectionInterval > GetAdjustedTime()))
                return error("GetKernelStakeModifier() : reached best block at height %d from block at height %d",
                             pindex->nHeight, pindexFrom->nHeight);
            else
                return false;
        }
        pindex = chainActive.Next(pindex);
        if (pindex->GeneratedStakeModifier()) {
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    cacheAdd(entry, nStakeModifier);
    return true;
}

// PoSV kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.block.nTime + txPrev.offset + txPrev.nTime + txPrev.vout.n + nTime) < bnTarget * nCoinDayWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier: scrambles computation to make it very difficult to precompute
//                  future proof-of-stake at the time of the coin's confirmation
//   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
//                       generate transaction for future advantage
//   txPrev.offset: offset of txPrev inside block, to reduce the chance of
//                  nodes generating coinstake at the same time
//   txPrev.nTime: reduce the chance of nodes generating coinstake at the same
//                 time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHash(unsigned int nBits, const CBlockHeader& blockFrom, unsigned int nTxPrevOffset, const CTransactionRef& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, bool fPrintProofOfStake)
{
    unsigned int nTimeBlockFrom = blockFrom.nTime;
    unsigned int nTimeTxPrev = txPrev->nTime;

    // deal with missing timestamps in PoW blocks
    if (nTimeTxPrev == 0)
        nTimeTxPrev = nTimeBlockFrom;

    if (nTimeTx < nTimeTxPrev) {// Transaction timestamp violation
        LogPrintf("WARNING: %s nTime violation: nTimeTx=%d < nTimeTxPrev=%d \n", __func__, nTimeTx, nTimeTxPrev);
        return false;
    }

    if (nTimeBlockFrom + Params().GetConsensus().nStakeMinAge > nTimeTx){ // Min age requirement
        LogPrintf("WARNING: %s min age violation \n", __func__);
        return false;
    }

    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    int64_t nValueIn = txPrev->vout[prevout.n].nValue;
    uint256 hashBlockFrom = blockFrom.GetHash();
    arith_uint256 bnCoinDayWeight = arith_uint256(nValueIn) * GetCoinAgeWeight((int64_t)nTimeTxPrev, (int64_t)nTimeTx) / COIN / (24 * 60 * 60);

    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
    uint64_t nStakeModifier = 0;
    int nStakeModifierHeight = 0;
    int64_t nStakeModifierTime = 0;

    if (!GetKernelStakeModifier(hashBlockFrom, nStakeModifier, nStakeModifierHeight, nStakeModifierTime, fPrintProofOfStake)){
        LogPrintf("WARNING: %s:  unable to determine stakemodifier nStakeModifier=%s, nStakeModifierHeight=%d, nStakeModifierTime=%d\n", __func__, nStakeModifier, nStakeModifierHeight, nStakeModifierTime);
        return false;
    }

    ss << nStakeModifier;
    ss << nTimeBlockFrom << nTxPrevOffset << nTimeTxPrev << prevout.n << nTimeTx;
    hashProofOfStake = Hash(ss.begin(), ss.end());

    if (fPrintProofOfStake) {
        LogPrintf("CheckStakeKernelHash() : using modifier 0x%016x at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
                  nStakeModifier, nStakeModifierHeight,
                  FormatISO8601DateTime( nStakeModifierTime),
                  mapBlockIndex[hashBlockFrom]->nHeight,
                  FormatISO8601DateTime(blockFrom.GetBlockTime()));
        LogPrintf("CheckStakeKernelHash() : check modifier=0x%016x nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
                  nStakeModifier,
                  nTimeBlockFrom, nTxPrevOffset, nTimeTxPrev, prevout.n, nTimeTx,
                  hashProofOfStake.ToString().c_str());
    }

    // Convert type so it can be compared to target
    arith_uint256 hashProof(hashProofOfStake.GetHex());
    arith_uint256 targetProof(bnTargetPerCoinDay.GetHex());
    targetProof *= bnCoinDayWeight;

    // Now check if proof-of-stake hash meets target protocol
    if (hashProof > targetProof){
        if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrintf("ERROR: %s hashProof=%d > targetProof=%d \n",__func__, hashProof.GetCompact(), targetProof.GetCompact());
        return false;
    }else
        return true;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(CValidationState &state, const CTransactionRef& tx, unsigned int nBits, uint256& hashProofOfStake)
{
    if (!tx->IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s \n", tx->GetHash().ToString().c_str());

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx->vin[0];

    // Transaction index is required to get to block header
    if (!g_txindex)
        return error("CheckProofOfStake() : transaction index not available \n");
    
    // Get transaction index for the previous transaction
    CDiskTxPos postx;
    if (!g_txindex->FindTxPosition(txin.prevout.hash, postx))
        return error("CheckProofOfStake() : tx index not found \n");  // tx index not found


    // Read txPrev and header of its block
    CBlockHeader header;
    CTransactionRef txPrev;
    {
        CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
        try {
            file >> header;
            fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
            file >> txPrev;
        } catch (std::exception &e) {
            return error("%s() : deserialize or I/O error in CheckProofOfStake()", __PRETTY_FUNCTION__);
        }
        if (txPrev->GetHash() != txin.prevout.hash)
            return error("%s() : txid mismatch in CheckProofOfStake()", __PRETTY_FUNCTION__);
    }

    // Verify signature
    {
        int nIn = 0;
        const CTxOut& prevOut = txPrev->vout[tx->vin[nIn].prevout.n];
        TransactionSignatureChecker checker(&(*tx), nIn, prevOut.nValue, PrecomputedTransactionData(*tx));

        if (!VerifyScript(tx->vin[nIn].scriptSig, prevOut.scriptPubKey, &(tx->vin[nIn].scriptWitness), SCRIPT_VERIFY_P2SH, checker, nullptr))
            return state.DoS(100, false, REJECT_INVALID, "invalid-pos-script", false, strprintf("%s: VerifyScript failed on coinstake %s", __func__, tx->GetHash().ToString()));
            //return error("%s: VerifyScript failed on coinstake %s", __func__, tx->GetHash().ToString());
    }

    if (!CheckStakeKernelHash(nBits, header, txin.prevout.n, txPrev, txin.prevout, tx->nTime, hashProofOfStake, gArgs.GetBoolArg("-printstakemodifier", false))){
        //LogPrintf("WARNING: %s check kernel failed on coinstake %s, hashProof=%s",__func__, tx->GetHash().ToString().c_str(), hashProofOfStake.ToString().c_str()); // may occur during initial download or if behind on block chain sync
        //return false;
        return state.DoS(1, error("CheckProofOfStake() : INFO: check kernel failed on coinstake %s, hashProof=%s", tx->GetHash().ToString(), hashProofOfStake.ToString())); // may occur during initial download or if behind on block chain sync
    }

    return true;
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx)
{
    // v0.3 protocol
    return (nTimeBlock == nTimeTx);
}

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    assert(pindex->pprev || pindex->GetBlockHash() == (Params().GetConsensus().hashGenesisBlock));
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << (pindex->IsProofOfStake() ? pindex->hashProof : uint256()) << pindex->nStakeModifier;
    arith_uint256 hashChecksum = UintToArith256(Hash(ss.begin(), ss.end()));
    hashChecksum >>= (256 - 32);
    return hashChecksum.GetLow64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, uint64_t nStakeModifierChecksum)
{
    if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrintf("CheckStakeModifierCheckpoints : nHeight=%d, nStakeModifierChecksum=0x%016x\n", nHeight, nStakeModifierChecksum);

    MapModifierCheckpoints& checkpoints = gArgs.GetBoolArg("-testnet", false) ? mapStakeModifierCheckpointsTestNet : mapStakeModifierCheckpoints;
    if (checkpoints.count(nHeight))
        return nStakeModifierChecksum == checkpoints[nHeight];
    return true;
}


// PoSV: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.

uint64_t GetCoinAge(const CTransaction& tx)
{
    arith_uint256 bnCentSecond = 0; // coin age in the unit of cent-seconds
    uint64_t nCoinAge = 0;

    if (tx.IsCoinBase())
        return 0;

    BOOST_FOREACH (const CTxIn& txin, tx.vin) {
        // First try finding the previous transaction in database
        CTransactionRef txPrevious;
        uint256 hashTxPrev = txin.prevout.hash;
        uint256 hashBlock = uint256();
        if (!GetTransaction(hashTxPrev, txPrevious, Params().GetConsensus(), hashBlock, true))
            continue; // previous transaction not in main chain
        CMutableTransaction txPrev(*txPrevious);
        // Read block header
        CBlock block;
        if (!mapBlockIndex.count(hashBlock))
            return 0; // unable to read block of previous transaction
        if (!ReadBlockFromDisk(block, mapBlockIndex[hashBlock], Params().GetConsensus()))
            return 0; // unable to read block of previous transaction
        if (block.nTime + Params().GetConsensus().nStakeMinAge > tx.nTime)
            continue; // only count coins meeting min age requirement

        // deal with missing timestamps in PoW blocks
        if (txPrev.nTime == 0)
            txPrev.nTime = block.nTime;

        if (tx.nTime < txPrev.nTime)
            return 0; // Transaction timestamp violation

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        int64_t nTimeWeight = GetCoinAgeWeight(txPrev.nTime, tx.nTime);
        bnCentSecond += arith_uint256(nValueIn) * nTimeWeight / CENT;

        if (gArgs.GetBoolArg("-printcoinage", false))
            LogPrintf("coin age nValueIn=%s nTime=%d, txPrev.nTime=%d, nTimeWeight=%s bnCentSecond=%s\n",
                      nValueIn, tx.nTime, txPrev.nTime, nTimeWeight, bnCentSecond.ToString().c_str());
    }

    arith_uint256 bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (gArgs.GetBoolArg("-printcoinage", false))
        LogPrintf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = ArithToUint256(bnCoinDay).GetUint64(0);
    return nCoinAge;
}

// PoSV: total coin age spent in block, in the unit of coin-days.
uint64_t GetCoinAge(const CBlock& block)
{
    uint64_t nCoinAge = 0;

    for (const auto& tx : block.vtx)
        nCoinAge += GetCoinAge(*tx);

    if (gArgs.GetBoolArg("-printcoinage", false))
        LogPrintf("block coin age total nCoinDays=%s\n", nCoinAge);
    return nCoinAge;
}

// PoSV2 determine the current inflation rate
double GetInflation(const CBlockIndex* pindex)
{
	int64_t nMoneySupply = pindex->pprev->nMoneySupply;
	// some rounding for year/ leap year
	int64_t nBlocksPerDay = 1440; // generate block per 60sec
	int64_t nBlocksPerYear = ((365 * 33 + 8.0) / 33.0) * nBlocksPerDay;
	// month are a consistent period
	int64_t nBlocksPerMonth = nBlocksPerYear / 12;

	double nInflation = 0;
	int64_t nPoSVRewards = 0;

    if (pindex && pindex->nHeight >= Params().GetConsensus().nLastPowHeight ) {
        if (pindex->nHeight - Params().GetConsensus().nLastPowHeight < nBlocksPerMonth) {
            nBlocksPerMonth = pindex->nHeight - Params().GetConsensus().nLastPowHeight;
        }
    }

    // get previous block interval
    std::string strHash = chainActive[pindex->nHeight - nBlocksPerMonth]->GetBlockHash().GetHex();
    uint256 hash = uint256S(strHash);

    if (mapBlockIndex.count(hash) == 0)
        LogPrintf("- Hash block missing\n");

	int64_t nMoneySupplyPrev = mapBlockIndex[hash]->nMoneySupply;

	nPoSVRewards = nMoneySupply - nMoneySupplyPrev;
	nInflation = (double(nPoSVRewards) / double(nMoneySupply)) * 12 * 100;
    if (gArgs.GetBoolArg("-printstakemodifier", false))
	    LogPrintf("inflation - Block rewards in last interval = %s. Inflation1 = %s\n", FormatMoney(nPoSVRewards), nInflation);

	return nInflation;
}

// PoSV2 determine the inflation adjustment to apply
// look back over the last month of rewards (365.2424 / 12)
double GetInflationAdjustment(const CBlockIndex* pindex)
{
    int64_t nStart = GetTimeMicros();
    float nInflationTarget = 0.05;
    double dMaxThreshold = 5;
    double dMinThreshold = .5;
    int64_t nMoneySupply = pindex->pprev->nMoneySupply;

    // some rounding for year/ leap year
    int64_t nBlocksPerDay = 1440; // generate block per 60sec
    int64_t nBlocksPerYear = ((365 * 33 + 8.0) / 33.0) * nBlocksPerDay;
    // month are a consistent period
    int64_t nBlocksPerMonth = nBlocksPerYear / 12;
    int64_t nPoSVRewards = 0;

    if (pindex && pindex->nHeight >= Params().GetConsensus().nLastPowHeight) {
        if (pindex->nHeight - Params().GetConsensus().nLastPowHeight < nBlocksPerMonth) {
            nBlocksPerMonth = pindex->nHeight - Params().GetConsensus().nLastPowHeight;
        }
    }

    // get previous block interval
    std::string strHash = chainActive[pindex->nHeight - nBlocksPerMonth]->GetBlockHash().GetHex();
    uint256 hash = uint256S(strHash);

    if (mapBlockIndex.count(hash) == 0)
        LogPrintf("- Hash block missing\n");

    int64_t nMoneySupplyPrev = mapBlockIndex[hash]->nMoneySupply;
    int64_t nHeightPrev = mapBlockIndex[hash]->nHeight;

    nPoSVRewards = nMoneySupply - nMoneySupplyPrev;

    double nRatio = (double(nMoneySupply) / double(nPoSVRewards));
    double nRawInflationAdjustment = ((nInflationTarget / 12) * nRatio); // looking at the last month of blocks
    
    if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrintf("inflation - Block rewards in last interval = %s. Inflation2 = %s\n", FormatMoney(nPoSVRewards), GetInflation(pindex));

    double nInflationAdjustment = std::max(std::min(nRawInflationAdjustment, dMaxThreshold), dMinThreshold);

    if (gArgs.GetBoolArg("-printstakemodifier", false))
	    LogPrintf("inflation - Inflation Adjustment (Bounded) = %s. Using Max %s | Min %s thresholds\n", nInflationAdjustment, dMaxThreshold, dMinThreshold);

    int64_t nTime = GetTimeMicros() - nStart;
    if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrintf("bench - Inflation Unbound Adjustment = %s Using last %s blocks from height %s to height %s: %.2fms\n", nRawInflationAdjustment, nBlocksPerMonth, nHeightPrev, pindex->nHeight, nTime * 0.001);

    return nInflationAdjustment;
}

bool IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired)
{
    unsigned int nToCheck = 0;
    if (minVersion == 3)
    {
    	nToCheck = Params().GetConsensus().nToCheckBlockUpgradeMajority;
    }
    else if (minVersion == 4)
    {
    	nToCheck = Params().GetConsensus().nToCheckBlockUpgradeMajority_4;
    }
    else if (minVersion == 5)
    {
    	nToCheck = Params().GetConsensus().nToCheckBlockUpgradeMajority_5;
    }
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != nullptr; i++) {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }

    return (nFound >= nRequired);
}

// POSV: entropy bit for stake modifier if chosen by modifier
unsigned int GetStakeEntropyBit(const CBlock& block)
    {
        // Take last bit of block hash as entropy bit
        unsigned int nEntropyBit = (block.GetHash().GetCheapHash() & 1llu);
        if (gArgs.GetBoolArg("-printstakemodifier", false))
            LogPrintf("GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u\n", block.GetHash().ToString().c_str(), nEntropyBit);
        return nEntropyBit;
    }

/* Calculate PoSV Kernel
 */
double GetPoSVKernelPS(const CBlockIndex* blockindex)
{
    const Consensus::Params params = Params().GetConsensus();

    if (blockindex == NULL || blockindex->nHeight <= params.nLastPowHeight || blockindex->IsProofOfWork())
        return 0;

    double dStakeKernelsTriedAvg = GetDifficulty(blockindex) * 4294967296.0; // 2^32
    return dStakeKernelsTriedAvg / params.nPowTargetSpacing;
}

