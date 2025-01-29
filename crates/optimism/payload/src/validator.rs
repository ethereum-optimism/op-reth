use alloc::sync::Arc;
use alloy_consensus::Header;
use alloy_rpc_types_engine::{ExecutionPayload, PayloadError};
use derive_more::{Constructor, Deref};
use reth_optimism_forks::{OpHardfork, OpHardforks};
use reth_payload_validator::ExecutionPayloadValidator;
use reth_primitives::{BlockBody, BlockExt, SealedBlock};
use reth_primitives_traits::SignedTransaction;
use reth_provider::StateProviderFactory;
use tracing::error;
use reth_optimism_consensus::OpConsensusError;
use reth_optimism_primitives::ADDRESS_L2_TO_L1_MESSAGE_PASSER;

/// Execution payload validator.
#[derive(Clone, Debug, Deref, Constructor)]
pub struct OpExecutionPayloadValidator<ChainSpec, P> {
    /// Chain spec to validate against.
    #[deref]
    inner: ExecutionPayloadValidator<ChainSpec>,
    state_provider: Arc<P>,
}

impl<ChainSpec, P> OpExecutionPayloadValidator<ChainSpec, P>
where
    ChainSpec: OpHardforks,
    P: StateProviderFactory,
{
    /// Ensures that the given payload does not violate any consensus rules that concern the block's
    /// layout, like:
    ///    - missing or invalid base fee
    ///    - invalid extra data
    ///    - invalid transactions
    ///    - incorrect hash
    ///    - the versioned hashes passed with the payload do not exactly match transaction versioned
    ///      hashes
    ///    - the block does not contain blob transactions if it is pre-cancun
    ///
    /// The checks are done in the order that conforms with the engine-API specification.
    ///
    /// This is intended to be invoked after receiving the payload from the CLI.
    /// The additional [`MaybeCancunPayloadFields`] are not part of the payload, but are additional fields in the `engine_newPayloadV3` RPC call, See also <https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#engine_newpayloadv3>
    ///
    /// If the cancun fields are provided this also validates that the versioned hashes in the block
    /// match the versioned hashes passed in the
    /// [`CancunPayloadFields`](alloy_rpc_types::engine::CancunPayloadFields), if the cancun payload
    /// fields are provided. If the payload fields are not provided, but versioned hashes exist
    /// in the block, this is considered an error: [`PayloadError::InvalidVersionedHashes`].
    ///
    /// This validates versioned hashes according to the Engine API Cancun spec:
    /// <https://github.com/ethereum/execution-apis/blob/fe8e13c288c592ec154ce25c534e26cb7ce0530d/src/engine/cancun.md#specification>
    pub fn ensure_well_formed_payload<T: SignedTransaction>(
        &self,
        payload: ExecutionPayload,
    ) -> Result<SealedBlock<Header, BlockBody<T>>, PayloadError> {
        let expected_hash = payload.block_hash();

        // First parse the block
        let mut block = payload.try_into_block()?;

        if self
            .chain_spec()
            .is_fork_active_at_timestamp(OpHardfork::Isthmus, block.timestamp)
        {
            let state = match self.state_provider.latest() {
                Ok(s) => s,
                Err(err) => {
                    error!(target: "payload_builder",
                        %err,
                        "Failed loading state to verify withdrawals storage root"
                    );

                    // this is just placeholder until this function can be updated to return a new
                    // OpPayloadError
                    return Err(PayloadError::InvalidVersionedHashes)
                }
            };

            // replace the withdrawals root computed by alloy from the block body withdrawals (hack)
            block.header.withdrawals_root =
                match state.storage_root(ADDRESS_L2_TO_L1_MESSAGE_PASSER, Default::default()).map_err(OpConsensusError::StorageRootCalculationFail) {
                    Ok(root) => Some(root),
                    Err(err) => {
                        error!(target: "payload_builder",
                            %err,
                            "Withdrawals storage root failed verification"
                        );

                        // this is just placeholder until this function can be updated to return a
                        // new OpPayloadError
                        return Err(PayloadError::InvalidVersionedHashes)
                    }
                };
        }

        let sealed_block = block.seal_slow();

        // Ensure the hash included in the payload matches the block hash
        if expected_hash != sealed_block.hash() {
            return Err(PayloadError::BlockHash {
                execution: sealed_block.hash(),
                consensus: expected_hash,
            })
        }

        if sealed_block.body().has_eip4844_transactions() {
            // cancun not active but blob transactions present
            return Err(PayloadError::PreCancunBlockWithBlobTransactions)
        }

        if self.chain_spec().is_cancun_active_at_timestamp(sealed_block.timestamp) {
            if sealed_block.blob_gas_used.is_none() {
                // cancun active but blob gas used not present
                return Err(PayloadError::PostCancunBlockWithoutBlobGasUsed)
            }
            if sealed_block.excess_blob_gas.is_none() {
                // cancun active but excess blob gas not present
                return Err(PayloadError::PostCancunBlockWithoutExcessBlobGas)
            }
        } else {
            if sealed_block.blob_gas_used.is_some() {
                // cancun not active but blob gas used present
                return Err(PayloadError::PreCancunBlockWithBlobGasUsed)
            }
            if sealed_block.excess_blob_gas.is_some() {
                // cancun not active but excess blob gas present
                return Err(PayloadError::PreCancunBlockWithExcessBlobGas)
            }
        }

        let shanghai_active =
            self.chain_spec().is_shanghai_active_at_timestamp(sealed_block.timestamp);
        if !shanghai_active && sealed_block.body().withdrawals.is_some() {
            // shanghai not active but withdrawals present
            return Err(PayloadError::PreShanghaiBlockWithWithdrawals)
        }

        if !self.chain_spec().is_prague_active_at_timestamp(sealed_block.timestamp) &&
            sealed_block.body().has_eip7702_transactions()
        {
            return Err(PayloadError::PrePragueBlockWithEip7702Transactions)
        }

        Ok(sealed_block)
    }
}
