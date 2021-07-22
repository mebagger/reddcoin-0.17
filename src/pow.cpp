// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

typedef int64_t int64;
typedef uint64_t uint64;

// PoSV: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int static KimotoGravityWell(const CBlockIndex* pindexLast, const CBlockHeader *pblock, uint64_t TargetBlocksSpacingSeconds, uint64_t PastBlocksMin, uint64_t PastBlocksMax)
{
    const CBlockIndex  *BlockLastSolved = pindexLast;
    const CBlockIndex  *BlockReading    = pindexLast;

    uint64_t  PastBlocksMass        = 0;
    int64_t   PastRateActualSeconds = 0;
    int64_t   PastRateTargetSeconds = 0;
    double  PastRateAdjustmentRatio = double(1);
    arith_uint256 PastDifficultyAverage;
    arith_uint256 PastDifficultyAveragePrev;
    arith_uint256 bnProofOfWorkLimit = UintToArith256(params.powLimit);
    arith_uint256 BlockReadingDifficulty;
    arith_uint256 bnProofOfStakeLimit = UintToArith256(params.bnProofOfStakeLimit);
    arith_uint256 bnProofOfStakeReset = UintToArith256(params.bnProofOfStakeReset);

    double EventHorizonDeviation;
    double EventHorizonDeviationFast;
    double EventHorizonDeviationSlow;

    bool fProofOfStake = false;
    if (pindexLast && pindexLast->nHeight >= params.nLastProofOfWorkHeight)
        fProofOfStake = true;

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || (uint64_t)BlockLastSolved->nHeight < PastBlocksMin)
    {
        return bnProofOfWorkLimit.GetCompact();
    }
    else if (fProofOfStake && (uint64_t)(BlockLastSolved->nHeight - params.nLastProofOfWorkHeight) < PastBlocksMin)
    {
        // difficulty is reset at the first PoSV blocks
        if (params.fPowAllowMinDifficultyBlocks)
            return bnProofOfStakeLimit.GetCompact();
        else
            return bnProofOfStakeReset.GetCompact();
    }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > (fProofOfStake ? params.nLastProofOfWorkHeight : 0); i++)
    {
        if (PastBlocksMax > 0 && i > PastBlocksMax)
            break;

        PastBlocksMass++;

        if (i == 1)
        {
            PastDifficultyAverage.SetCompact(BlockReading->nBits);
        }
        else
        {
            BlockReadingDifficulty.SetCompact(BlockReading->nBits);
            if (BlockReadingDifficulty > PastDifficultyAveragePrev) {
                PastDifficultyAverage = PastDifficultyAveragePrev + ((BlockReadingDifficulty - PastDifficultyAveragePrev) / i);
            } else {
                PastDifficultyAverage = PastDifficultyAveragePrev - ((PastDifficultyAveragePrev - BlockReadingDifficulty) / i);
            }
        }
        PastDifficultyAveragePrev = PastDifficultyAverage;

        PastRateActualSeconds = BlockLastSolved->GetBlockTime() - BlockReading->GetBlockTime();
        PastRateTargetSeconds = TargetBlocksSpacingSeconds * PastBlocksMass;
        PastRateAdjustmentRatio = double(1);

        if (PastRateActualSeconds < 0)
            PastRateActualSeconds = 0;

        if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0)
            PastRateAdjustmentRatio = double(PastRateTargetSeconds) / double(PastRateActualSeconds);

        EventHorizonDeviation = 1 + (0.7084 * pow((double(PastBlocksMass)/double(144)), -1.228));
        EventHorizonDeviationFast = EventHorizonDeviation;
        EventHorizonDeviationSlow = 1 / EventHorizonDeviation;

        if (PastBlocksMass >= PastBlocksMin)
        {
            if ((PastRateAdjustmentRatio <= EventHorizonDeviationSlow) || (PastRateAdjustmentRatio >= EventHorizonDeviationFast))
            {
                assert(BlockReading);
                break;
            }
        }

        if (BlockReading->pprev == NULL)
        {
            assert(BlockReading);
            break;
        }

        BlockReading = BlockReading->pprev;

    }

    arith_uint256 bnNew(PastDifficultyAverage);

    if (PastRateActualSeconds != 0 && PastRateTargetSeconds != 0)
    {
        bnNew *= PastRateActualSeconds;
        bnNew /= PastRateTargetSeconds;
    }

    if (!fProofOfStake && bnNew > bnProofOfWorkLimit)
    {
        bnNew = bnProofOfWorkLimit;
    }
    else if (fProofOfStake && bnNew > bnProofOfStakeLimit)
    {
        bnNew = bnProofOfStakeLimit;
    }

	LogPrint("kgw", "Difficulty Retarget - Kimoto Gravity Well\n");
	LogPrint("kgw", "PastRateAdjustmentRatio = %g\n", PastRateAdjustmentRatio);
	LogPrint("kgw", "Before: %08x  %s\n", BlockLastSolved->nBits, arith_uint256().SetCompact(BlockLastSolved->nBits).ToString().c_str());
	LogPrint("kgw", "After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString().c_str());

     return bnNew.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // always mine PoW blocks at the lowest diff on testnet
    if (params.fPowAllowMinDifficultyBlocks && pindexLast->nHeight < params.nLastProofOfWorkHeight)
        return nProofOfWorkLimit;

    static const int64_t BlocksTargetSpacing = 1 * 60; // 1 Minute
    unsigned int TimeDaySeconds = 60 * 60 * 24;

    int64_t PastSecondsMin = TimeDaySeconds * 0.25;
    int64_t PastSecondsMax = TimeDaySeconds * 7;

    if (pindexLast->nHeight < 6000)
    {
        PastSecondsMin = TimeDaySeconds * 0.01;
        PastSecondsMax = TimeDaySeconds * 0.14;
    }

    uint64_t PastBlocksMin = PastSecondsMin / BlocksTargetSpacing;
    uint64_t PastBlocksMax = PastSecondsMax / BlocksTargetSpacing;

   	LogPrint("kgw", "%s : Height = %s (%s) PastBlocksMin = %s, PastBlocksMax = %s \n", __func__, pindexLast->nHeight, pindexLast->GetBlockHash().ToString(), PastBlocksMin, PastBlocksMax);

    return KimotoGravityWell(pindexLast, pblock, BlocksTargetSpacing, PastBlocksMin, PastBlocksMax);
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
