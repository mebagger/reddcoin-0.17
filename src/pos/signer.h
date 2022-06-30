// Copyright (c) 2014-2021 The Reddcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCKSIGNATURE_H
#define BLOCKSIGNATURE_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <wallet/wallet.h>

bool SignBlock(CBlock& block, const CKeyStore& keystore);
bool CheckBlockSignature(const CBlock& block);

#endif // BLOCKSIGNATURE_H