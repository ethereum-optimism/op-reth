//! Canyon consensus rule checks.

use alloy_consensus::BlockHeader;
use alloy_trie::EMPTY_ROOT_HASH;
use reth_consensus::ConsensusError;
use reth_primitives::GotExpected;
use reth_primitives_traits::BlockBody;

use crate::OpConsensusError;

/// Validate that withdrawals in block body (Shanghai) is always empty in Canyon.
/// <https://specs.optimism.io/protocol/rollup-node-p2p.html#block-validation>
#[inline]
pub fn validate_empty_shanghai_withdrawals<B: BlockBody>(body: &B) -> Result<(), OpConsensusError> {
    // Shanghai rule
    let withdrawals = body.withdrawals().ok_or(ConsensusError::BodyWithdrawalsMissing)?;

    //  Canyon rule
    if !withdrawals.is_empty() {
        return Err(OpConsensusError::WithdrawalsNonEmpty)
    }

    Ok(())
}

/// Validate that withdrawals root in block header (Shanghai) is always [`EMPTY_ROOT_HASH`] in
/// Canyon.
#[inline]
pub fn validate_empty_withdrawals_root<H: BlockHeader>(header: &H) -> Result<(), ConsensusError> {
    // Shanghai rule
    let header_withdrawals_root =
        header.withdrawals_root().ok_or(ConsensusError::WithdrawalsRootMissing)?;

    //  Canyon rules
    if header_withdrawals_root != EMPTY_ROOT_HASH {
        return Err(ConsensusError::BodyWithdrawalsRootDiff(
            GotExpected { got: header_withdrawals_root, expected: EMPTY_ROOT_HASH }.into(),
        ));
    }

    Ok(())
}
