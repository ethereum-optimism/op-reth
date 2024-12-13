//! Block validation w.r.t. consensus rules new in isthmus hardfork.

use alloy_consensus::BlockHeader;
use reth_optimism_primitives::predeploys::ADDRESS_L2_TO_L1_MESSAGE_PASSER;
use reth_storage_api::{StateProviderFactory, StorageRootProvider};

use crate::OpConsensusError;

/// Validates block header field `withdrawals_root` against storage root of
/// `2toL1-message-passer` predeploy.
pub fn validate_l2_to_l1_msg_passer<H: BlockHeader, P: StateProviderFactory>(
    provider: &P,
    header: &H,
) -> Result<(), OpConsensusError> {
    let header_storage_root =
        header.withdrawals_root().ok_or(OpConsensusError::StorageRootMissing)?;

    let state = provider.latest().map_err(OpConsensusError::LoadStorageRootFailed)?;

    let storage_root = state
        .storage_root(ADDRESS_L2_TO_L1_MESSAGE_PASSER, Default::default())
        .map_err(OpConsensusError::LoadStorageRootFailed)?;

    if header_storage_root != storage_root {
        return Err(OpConsensusError::StorageRootMismatch {
            got: header_storage_root,
            expected: storage_root,
        })
    }

    Ok(())
}
