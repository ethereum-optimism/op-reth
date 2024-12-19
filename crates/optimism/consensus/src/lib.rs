//! Optimism Consensus implementation.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/paradigmxyz/reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
// The `optimism` feature must be enabled to use this crate.
#![cfg(feature = "optimism")]

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;

use alloy_consensus::{BlockHeader, Header, EMPTY_OMMER_ROOT_HASH};
use alloy_primitives::{B64, U256};
use reth_chainspec::EthereumHardforks;
use reth_consensus::{
    Consensus, ConsensusError, FullConsensus, HeaderValidator, PostExecutionInput,
};
use reth_consensus_common::validation::{
    validate_against_parent_4844, validate_against_parent_eip1559_base_fee,
    validate_against_parent_hash_number, validate_against_parent_timestamp,
    validate_body_against_header, validate_cancun_gas, validate_header_base_fee,
    validate_header_extra_data, validate_header_gas,
};
use reth_optimism_chainspec::OpChainSpec;
use reth_optimism_forks::OpHardforks;
use reth_optimism_primitives::OpPrimitives;
use reth_primitives::{BlockBody, BlockWithSenders, GotExpected, SealedBlock, SealedHeader};
use reth_storage_api::StateProviderFactory;
use std::time::SystemTime;
use tracing::trace;

pub mod error;
pub use error::OpConsensusError;

mod proof;
pub use proof::calculate_receipt_root_no_memo_optimism;

mod validation;
pub use validation::{canyon, isthmus, validate_block_post_execution};

/// Optimism consensus implementation.
///
/// Provides basic checks as outlined in the execution specs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpBeaconConsensus<P> {
    /// Configuration
    chain_spec: Arc<OpChainSpec>,
    provider: P,
}

impl<P> OpBeaconConsensus<P> {
    /// Create a new instance of [`OpBeaconConsensus`]
    pub const fn new(chain_spec: Arc<OpChainSpec>, provider: P) -> Self {
        Self { chain_spec, provider }
    }
}

impl<P> FullConsensus<OpPrimitives> for OpBeaconConsensus<P>
where
    P: StateProviderFactory + fmt::Debug,
{
    fn validate_block_post_execution(
        &self,
        block: &BlockWithSenders,
        input: PostExecutionInput<'_>,
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution(
            block,
            &self.chain_spec,
            input.receipts,
            Some(input.state),
            Some(&self.provider),
        )
    }
}

impl<P> Consensus for OpBeaconConsensus<P>
where
    P: StateProviderFactory + fmt::Debug,
{
    fn validate_body_against_header(
        &self,
        body: &BlockBody,
        header: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        validate_body_against_header(body, header.header())
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock) -> Result<(), ConsensusError> {
        // Check ommers hash
        let ommers_hash = reth_primitives::proofs::calculate_ommers_root(&block.body.ommers);
        if block.header.ommers_hash != ommers_hash {
            return Err(ConsensusError::BodyOmmersHashDiff(
                GotExpected { got: ommers_hash, expected: block.header.ommers_hash }.into(),
            ))
        }

        // Check transaction root
        if let Err(error) = block.ensure_transaction_root_valid() {
            return Err(ConsensusError::BodyTransactionRootDiff(error.into()))
        }

        // Check empty shanghai-withdrawals
        if self.chain_spec.is_canyon_active_at_timestamp(block.timestamp) {
            canyon::validate_empty_shanghai_withdrawals(&block.body).map_err(|err| {
                trace!(target: "op::consensus",
                    block_number=block.number(),
                    %err,
                    "block failed validation",
                );

                ConsensusError::Other
            })?;
        } else {
            return Ok(())
        }

        if self.chain_spec.is_cancun_active_at_timestamp(block.timestamp) {
            validate_cancun_gas(block)?;
        } else {
            return Ok(())
        }

        if !self.chain_spec.is_isthmus_active_at_timestamp(block.timestamp) {
            // canyon is active, else would already have returned
            canyon::validate_empty_withdrawals_root(&block.header)?;
        }

        Ok(())
    }
}

impl<P> HeaderValidator for OpBeaconConsensus<P>
where
    P: Send + Sync + fmt::Debug,
{
    fn validate_header(&self, header: &SealedHeader) -> Result<(), ConsensusError> {
        validate_header_gas(header.header())?;
        validate_header_base_fee(header.header(), &self.chain_spec)
    }

    fn validate_header_against_parent(
        &self,
        header: &SealedHeader,
        parent: &SealedHeader,
    ) -> Result<(), ConsensusError> {
        validate_against_parent_hash_number(header.header(), parent)?;

        if self.chain_spec.is_bedrock_active_at_block(header.number) {
            validate_against_parent_timestamp(header.header(), parent.header())?;
        }

        // EIP1559 base fee validation
        // <https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/holocene/exec-engine.md#base-fee-computation>
        // > if Holocene is active in parent_header.timestamp, then the parameters from
        // > parent_header.extraData are used.
        if self.chain_spec.is_holocene_active_at_timestamp(parent.timestamp) {
            let header_base_fee =
                header.base_fee_per_gas().ok_or(ConsensusError::BaseFeeMissing)?;
            let expected_base_fee = self
                .chain_spec
                .decode_holocene_base_fee(parent, header.timestamp)
                .map_err(|_| ConsensusError::BaseFeeMissing)?;
            if expected_base_fee != header_base_fee {
                return Err(ConsensusError::BaseFeeDiff(GotExpected {
                    expected: expected_base_fee,
                    got: header_base_fee,
                }))
            }
        } else {
            validate_against_parent_eip1559_base_fee(
                header.header(),
                parent.header(),
                &self.chain_spec,
            )?;
        }

        // ensure that the blob gas fields for this block
        if self.chain_spec.is_cancun_active_at_timestamp(header.timestamp) {
            validate_against_parent_4844(header.header(), parent.header())?;
        }

        Ok(())
    }

    fn validate_header_with_total_difficulty(
        &self,
        header: &Header,
        _total_difficulty: U256,
    ) -> Result<(), ConsensusError> {
        // with OP-stack Bedrock activation number determines when TTD (eth Merge) has been reached.
        let is_post_merge = self.chain_spec.is_bedrock_active_at_block(header.number);

        if is_post_merge {
            if header.nonce != B64::ZERO {
                return Err(ConsensusError::TheMergeNonceIsNotZero)
            }

            if header.ommers_hash != EMPTY_OMMER_ROOT_HASH {
                return Err(ConsensusError::TheMergeOmmerRootIsNotEmpty)
            }

            // Post-merge, the consensus layer is expected to perform checks such that the block
            // timestamp is a function of the slot. This is different from pre-merge, where blocks
            // are only allowed to be in the future (compared to the system's clock) by a certain
            // threshold.
            //
            // Block validation with respect to the parent should ensure that the block timestamp
            // is greater than its parent timestamp.

            // validate header extra data for all networks post merge
            validate_header_extra_data(header)?;

            // mixHash is used instead of difficulty inside EVM
            // https://eips.ethereum.org/EIPS/eip-4399#using-mixhash-field-instead-of-difficulty
        } else {
            // Check if timestamp is in the future. Clock can drift but this can be consensus issue.
            let present_timestamp =
                SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();

            if header.exceeds_allowed_future_timestamp(present_timestamp) {
                return Err(ConsensusError::TimestampIsInFuture {
                    timestamp: header.timestamp,
                    present_timestamp,
                })
            }
        }

        Ok(())
    }
}
