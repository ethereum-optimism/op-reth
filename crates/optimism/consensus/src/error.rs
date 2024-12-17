//! Optimism consensus errors

use alloy_primitives::B256;
use derive_more::{Display, Error, From};
use reth_consensus::ConsensusError;
use reth_storage_errors::provider::ProviderError;

/// Optimism consensus error.
#[derive(Debug, PartialEq, Eq, Clone, Display, Error, From)]
pub enum OpConsensusError {
    /// Block body has non-empty withdrawals list.
    #[display("non-empty withdrawals list")]
    WithdrawalsNonEmpty,
    /// Failed to load storage root of
    /// [`L2toL1MessagePasser`](reth_optimism_primitives::ADDRESS_L2_TO_L1_MESSAGE_PASSER).
    #[display("failed to load storage root of L2toL1MessagePasser pre-deploy: {_0}")]
    #[from]
    LoadStorageRootFailed(ProviderError),
    /// Storage root of
    /// [`L2toL1MessagePasser`](reth_optimism_primitives::ADDRESS_L2_TO_L1_MESSAGE_PASSER) missing
    /// in block header (withdrawals root field).
    #[display("storage root of l2tol1-msg-passer predeploy missing from block header (withdrawals root field empty)")]
    StorageRootMissing,
    /// Storage root of
    /// [`L2toL1MessagePasser`](reth_optimism_primitives::ADDRESS_L2_TO_L1_MESSAGE_PASSER)
    /// in block header (withdrawals field), doesn't match local storage root.
    #[display("l2tol1-msg-passer storage root mismatch, block: {block}, local: {local}")]
    StorageRootMismatch {
        /// Storage root of pre-deploy in block.
        block: B256,
        /// Storage root of pre-deploy loaded from local state.
        local: B256,
    },
    /// L1 [`ConsensusError`], that also occurs on L2.
    #[display("{_0}")]
    #[from]
    Eth(ConsensusError),
}
