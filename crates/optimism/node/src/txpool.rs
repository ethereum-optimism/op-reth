//! OP transaction pool types
use alloy_consensus::{
    BlobTransactionSidecar, BlobTransactionValidationError, BlockHeader, Transaction, Typed2718,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, TxHash, TxKind, U256};
use derive_more::Display;
use op_alloy_consensus::OpTypedTransaction;
use parking_lot::RwLock;
use reth_chainspec::ChainSpec;
use reth_node_api::{Block, BlockBody, ConfigureEvm, ConfigureEvmEnv};
use reth_optimism_evm::{OpEvmConfig, RethL1BlockInfo};
use reth_optimism_primitives::{OpBlock, OpTransactionSigned};
use reth_primitives::{
    transaction::TransactionConversionError, GotExpected, InvalidTransactionError, Recovered,
    SealedBlock,
};
use reth_primitives_traits::SignedTransaction;
use reth_provider::{BlockReaderIdExt, StateProviderFactory};
use reth_revm::{database::StateProviderDatabase, db::CacheDB, L1BlockInfo};
use reth_transaction_pool::{
    CoinbaseTipOrdering, EthBlobTransactionSidecar, EthPoolTransaction, EthPooledTransaction,
    EthTransactionValidator, Pool, PoolTransaction, TransactionOrigin,
    TransactionValidationOutcome, TransactionValidationTaskExecutor, TransactionValidator,
};
use revm::primitives::{AccessList, KzgSettings};
use revm_primitives::ResultAndState;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use tracing::{trace, warn};

/// Type alias for default optimism transaction pool
pub type OpTransactionPool<Client, S> = Pool<
    TransactionValidationTaskExecutor<OpTransactionValidator<Client, OpPooledTransaction>>,
    CoinbaseTipOrdering<OpPooledTransaction>,
    S,
>;

/// Pool transaction for OP.
///
/// This type wraps the actual transaction and caches values that are frequently used by the pool.
/// For payload building this lazily tracks values that are required during payload building:
///  - Estimated compressed size of this transaction
#[derive(Debug, Clone, derive_more::Deref)]
pub struct OpPooledTransaction {
    #[deref]
    inner: EthPooledTransaction<OpTransactionSigned>,
    /// The estimated size of this transaction, lazily computed.
    estimated_tx_compressed_size: OnceLock<u64>,
}

impl OpPooledTransaction {
    /// Create new instance of [Self].
    pub fn new(transaction: Recovered<OpTransactionSigned>, encoded_length: usize) -> Self {
        Self {
            inner: EthPooledTransaction::new(transaction, encoded_length),
            estimated_tx_compressed_size: Default::default(),
        }
    }

    /// Returns the estimated compressed size of a transaction in bytes scaled by 1e6.
    /// This value is computed based on the following formula:
    /// `max(minTransactionSize, intercept + fastlzCoef*fastlzSize)`
    pub fn estimated_compressed_size(&self) -> u64 {
        *self.estimated_tx_compressed_size.get_or_init(|| {
            op_alloy_flz::tx_estimated_size_fjord(&self.inner.transaction().encoded_2718())
        })
    }
}

impl From<Recovered<op_alloy_consensus::OpPooledTransaction>> for OpPooledTransaction {
    fn from(tx: Recovered<op_alloy_consensus::OpPooledTransaction>) -> Self {
        let encoded_len = tx.encode_2718_len();
        let tx = tx.map_transaction(|tx| tx.into());
        Self {
            inner: EthPooledTransaction::new(tx, encoded_len),
            estimated_tx_compressed_size: Default::default(),
        }
    }
}

impl TryFrom<Recovered<OpTransactionSigned>> for OpPooledTransaction {
    type Error = TransactionConversionError;

    fn try_from(value: Recovered<OpTransactionSigned>) -> Result<Self, Self::Error> {
        let (tx, signer) = value.into_parts();
        let pooled: Recovered<op_alloy_consensus::OpPooledTransaction> =
            Recovered::new_unchecked(tx.try_into()?, signer);
        Ok(pooled.into())
    }
}

impl From<OpPooledTransaction> for Recovered<OpTransactionSigned> {
    fn from(value: OpPooledTransaction) -> Self {
        value.inner.transaction
    }
}

impl PoolTransaction for OpPooledTransaction {
    type TryFromConsensusError = <Self as TryFrom<Recovered<Self::Consensus>>>::Error;
    type Consensus = OpTransactionSigned;
    type Pooled = op_alloy_consensus::OpPooledTransaction;

    fn clone_into_consensus(&self) -> Recovered<Self::Consensus> {
        self.inner.transaction().clone()
    }

    fn try_consensus_into_pooled(
        tx: Recovered<Self::Consensus>,
    ) -> Result<Recovered<Self::Pooled>, Self::TryFromConsensusError> {
        let (tx, signer) = tx.into_parts();
        Ok(Recovered::new_unchecked(tx.try_into()?, signer))
    }

    fn hash(&self) -> &TxHash {
        self.inner.transaction.tx_hash()
    }

    fn sender(&self) -> Address {
        self.inner.transaction.signer()
    }

    fn sender_ref(&self) -> &Address {
        self.inner.transaction.signer_ref()
    }

    fn nonce(&self) -> u64 {
        self.inner.transaction.nonce()
    }

    fn cost(&self) -> &U256 {
        &self.inner.cost
    }

    fn gas_limit(&self) -> u64 {
        self.inner.transaction.gas_limit()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.inner.transaction.transaction.max_fee_per_gas()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.inner.transaction.access_list()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.inner.transaction.transaction.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.inner.transaction.max_fee_per_blob_gas()
    }

    fn effective_tip_per_gas(&self, base_fee: u64) -> Option<u128> {
        self.inner.transaction.effective_tip_per_gas(base_fee)
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.inner.transaction.priority_fee_or_price()
    }

    fn kind(&self) -> TxKind {
        self.inner.transaction.kind()
    }

    fn is_create(&self) -> bool {
        self.inner.transaction.is_create()
    }

    fn input(&self) -> &[u8] {
        self.inner.transaction.input()
    }

    fn size(&self) -> usize {
        self.inner.transaction.transaction.input().len()
    }

    fn tx_type(&self) -> u8 {
        self.inner.transaction.ty()
    }

    fn encoded_length(&self) -> usize {
        self.inner.encoded_length
    }

    fn chain_id(&self) -> Option<u64> {
        self.inner.transaction.chain_id()
    }
}

impl EthPoolTransaction for OpPooledTransaction {
    fn take_blob(&mut self) -> EthBlobTransactionSidecar {
        EthBlobTransactionSidecar::None
    }

    fn blob_count(&self) -> usize {
        0
    }

    fn try_into_pooled_eip4844(
        self,
        _sidecar: Arc<BlobTransactionSidecar>,
    ) -> Option<Recovered<Self::Pooled>> {
        None
    }

    fn try_from_eip4844(
        _tx: Recovered<Self::Consensus>,
        _sidecar: BlobTransactionSidecar,
    ) -> Option<Self> {
        None
    }

    fn validate_blob(
        &self,
        _sidecar: &BlobTransactionSidecar,
        _settings: &KzgSettings,
    ) -> Result<(), BlobTransactionValidationError> {
        Err(BlobTransactionValidationError::NotBlobTransaction(self.tx_type()))
    }

    fn authorization_count(&self) -> usize {
        match &self.inner.transaction.transaction {
            OpTypedTransaction::Eip7702(tx) => tx.authorization_list.len(),
            _ => 0,
        }
    }
}

/// An interop transaction validation error.
#[derive(Debug, Display, Clone, PartialEq, Eq)]
pub enum InteropValidationError {
    /// Block fetch failed.
    #[display("latest block fetch failed")]
    BlockFetchFailed,
    /// Failed to load state.
    #[display("failed to load state")]
    StateLoadFailed,
    /// Transaction execution failed.
    #[display("transaction execution failed")]
    TxExecutionFailed,
}

impl core::error::Error for InteropValidationError {}

/// Validator for Optimism transactions.
#[derive(Debug, Clone)]
pub struct OpTransactionValidator<Client, Tx> {
    /// The type that performs the actual validation.
    inner: EthTransactionValidator<Client, Tx>,
    /// Additional block info required for validation.
    block_info: Arc<OpL1BlockInfo>,
    /// An optional `EvmConfig`.
    /// This should ONLY be set if interop is enabled.
    evm: Option<OpEvmConfig>,
    /// If true, ensure that the transaction's sender has enough balance to cover the L1 gas fee
    /// derived from the tracked L1 block info that is extracted from the first transaction in the
    /// L2 block.
    require_l1_data_gas_fee: bool,
}

impl<Client, Tx> OpTransactionValidator<Client, Tx> {
    /// Returns the configured chain spec
    pub fn chain_spec(&self) -> &Arc<ChainSpec> {
        self.inner.chain_spec()
    }

    /// Returns the configured client
    pub fn client(&self) -> &Client {
        self.inner.client()
    }

    /// Returns the current block timestamp.
    fn block_timestamp(&self) -> u64 {
        self.block_info.timestamp.load(Ordering::Relaxed)
    }

    /// Sets the `evm` on the [`OpTransactionValidator`].
    pub fn with_evm_config(self, evm_config: Option<OpEvmConfig>) -> Self {
        Self { evm: evm_config, ..self }
    }

    /// Whether to ensure that the transaction's sender has enough balance to also cover the L1 gas
    /// fee.
    pub fn require_l1_data_gas_fee(self, require_l1_data_gas_fee: bool) -> Self {
        Self { require_l1_data_gas_fee, ..self }
    }

    /// Returns whether this validator also requires the transaction's sender to have enough balance
    /// to cover the L1 gas fee.
    pub const fn requires_l1_data_gas_fee(&self) -> bool {
        self.require_l1_data_gas_fee
    }
}

impl<Client, Tx> OpTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory + BlockReaderIdExt<Block = OpBlock>,
    Tx: EthPoolTransaction<Consensus = OpTransactionSigned>,
{
    /// Create a new [`OpTransactionValidator`].
    pub fn new(inner: EthTransactionValidator<Client, Tx>) -> Self {
        let this = Self::with_block_info(inner, OpL1BlockInfo::default());
        if let Ok(Some(block)) =
            this.inner.client().block_by_number_or_tag(alloy_eips::BlockNumberOrTag::Latest)
        {
            // genesis block has no txs, so we can't extract L1 info, we set the block info to empty
            // so that we will accept txs into the pool before the first block
            if block.header().number() == 0 {
                this.block_info.timestamp.store(block.header().timestamp(), Ordering::Relaxed);
            } else {
                this.update_l1_block_info(block.header(), block.body().transactions().next());
            }
        }

        this
    }

    /// Create a new [`OpTransactionValidator`] with the given [`OpL1BlockInfo`].
    pub fn with_block_info(
        inner: EthTransactionValidator<Client, Tx>,
        block_info: OpL1BlockInfo,
    ) -> Self {
        Self { inner, block_info: Arc::new(block_info), evm: None, require_l1_data_gas_fee: true }
    }

    /// Update the L1 block info for the given header and system transaction, if any.
    ///
    /// Note: this supports optional system transaction, in case this is used in a dev setuo
    pub fn update_l1_block_info<H, T>(&self, header: &H, tx: Option<&T>)
    where
        H: BlockHeader,
        T: Transaction,
    {
        self.block_info.timestamp.store(header.timestamp(), Ordering::Relaxed);

        if let Some(Ok(cost_addition)) = tx.map(reth_optimism_evm::extract_l1_info_from_tx) {
            *self.block_info.l1_block_info.write() = cost_addition;
        }
    }

    /// Validates a single transaction.
    ///
    /// See also [`TransactionValidator::validate_transaction`]
    ///
    /// This behaves the same as [`EthTransactionValidator::validate_one`], but in addition, ensures
    /// that the account has enough balance to cover the L1 gas cost.
    pub fn validate_one(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
    ) -> TransactionValidationOutcome<Tx> {
        if transaction.is_eip4844() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::TxTypeNotSupported.into(),
            );
        }

        let outcome = self.inner.validate_one(origin, transaction);

        // ensure that the account has enough balance to cover the L1 gas cost
        if let TransactionValidationOutcome::Valid {
            balance,
            state_nonce,
            transaction: valid_tx,
            propagate,
        } = outcome
        {
            if self.requires_l1_data_gas_fee() {
                // need to check L1 gas fee

                let mut l1_block_info = self.block_info.l1_block_info.read().clone();

                let mut encoded = Vec::with_capacity(valid_tx.transaction().encoded_length());
                let tx = valid_tx.transaction().clone_into_consensus();
                tx.encode_2718(&mut encoded);

                let cost_addition = match l1_block_info.l1_tx_data_fee(
                    self.chain_spec(),
                    self.block_timestamp(),
                    &encoded,
                    false,
                ) {
                    Ok(cost) => cost,
                    Err(err) => {
                        return TransactionValidationOutcome::Error(*valid_tx.hash(), Box::new(err))
                    }
                };
                let cost = valid_tx.transaction().cost().saturating_add(cost_addition);

                // Checks for max cost
                if cost > balance {
                    return TransactionValidationOutcome::Invalid(
                        valid_tx.into_transaction(),
                        InvalidTransactionError::InsufficientFunds(
                            GotExpected { got: balance, expected: cost }.into(),
                        )
                        .into(),
                    );
                }
            }

            // If the EVM is configured, enable interop tx execution.
            if let Some(evm_cfg) = &self.evm {
                // Get the current block
                let block = if let Ok(Some(block)) =
                    self.inner.client().block_by_number_or_tag(alloy_eips::BlockNumberOrTag::Latest)
                {
                    block
                } else {
                    // Failure to get the latest block is a critical error.
                    // Transaction validation must be re-tried.
                    warn!(target: "reth::txpool",
                        "Transaction validation failed: could not get latest block (interop)"
                    );
                    return TransactionValidationOutcome::Error(
                        *valid_tx.hash(),
                        InteropValidationError::BlockFetchFailed.into(),
                    );
                };

                // Construct the state using the current block.
                let Ok(state) =
                    self.inner.client().state_by_block_hash(block.header().num_hash_slow().hash)
                else {
                    warn!(target: "reth::txpool",
                        "Transaction execution failed: failed to load state"
                    );
                    return TransactionValidationOutcome::Error(
                        *valid_tx.hash(),
                        InteropValidationError::StateLoadFailed.into(),
                    );
                };
                let mut db = CacheDB::new(StateProviderDatabase::new(&state));

                // Configure the evm
                let mut evm = evm_cfg.evm_for_block(&mut db, block.header());

                // Construct the environment for the transaction
                let sender = valid_tx.transaction().sender();
                let tx: &Tx = valid_tx.transaction();
                let inner_tx: Recovered<OpTransactionSigned> = tx.clone_into_consensus();
                let tx: &OpTransactionSigned = inner_tx.tx();
                let tx_env = evm_cfg.tx_env(tx, sender);
                *evm.tx_mut() = tx_env;

                // Transact
                let _logs = match evm.transact() {
                    Ok(ResultAndState { result, .. }) => result.into_logs(),
                    Err(err) => {
                        warn!(target: "reth::txpool",
                            %err,
                            "Transaction execution failed"
                        );
                        return TransactionValidationOutcome::Error(
                            *valid_tx.hash(),
                            InteropValidationError::TxExecutionFailed.into(),
                        );
                    }
                };
                trace!(target: "reth::txpool",
                    tx_hash = %valid_tx.hash(),
                    "Tx executed successfully"
                );
                // todo: parse logs to extract executing message if any (sync)
                // todo: if any executing message, return in valid variant as Some(msg)
                // todo: from caller of this func, make async call to supervisor api.
            }

            return TransactionValidationOutcome::Valid {
                balance,
                state_nonce,
                transaction: valid_tx,
                propagate,
            };
        }

        outcome
    }

    /// Validates all given transactions.
    ///
    /// Returns all outcomes for the given transactions in the same order.
    ///
    /// See also [`Self::validate_one`]
    pub fn validate_all(
        &self,
        transactions: Vec<(TransactionOrigin, Tx)>,
    ) -> Vec<TransactionValidationOutcome<Tx>> {
        transactions.into_iter().map(|(origin, tx)| self.validate_one(origin, tx)).collect()
    }
}

impl<Client, Tx> TransactionValidator for OpTransactionValidator<Client, Tx>
where
    Client: StateProviderFactory + BlockReaderIdExt<Block = OpBlock>,
    Tx: EthPoolTransaction<Consensus = OpTransactionSigned>,
{
    type Transaction = Tx;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        self.validate_one(origin, transaction)
    }

    async fn validate_transactions(
        &self,
        transactions: Vec<(TransactionOrigin, Self::Transaction)>,
    ) -> Vec<TransactionValidationOutcome<Self::Transaction>> {
        self.validate_all(transactions)
    }

    fn on_new_head_block<B>(&self, new_tip_block: &SealedBlock<B>)
    where
        B: Block,
    {
        self.inner.on_new_head_block(new_tip_block);
        self.update_l1_block_info(
            new_tip_block.header(),
            new_tip_block.body().transactions().first(),
        );
    }
}

/// Tracks additional infos for the current block.
#[derive(Debug, Default)]
pub struct OpL1BlockInfo {
    /// The current L1 block info.
    l1_block_info: RwLock<L1BlockInfo>,
    /// Current block timestamp.
    timestamp: AtomicU64,
}

#[cfg(test)]
mod tests {
    use crate::{
        txpool::{OpPooledTransaction, OpTransactionValidator},
        OpEvmConfig,
    };
    use alloy_consensus::{Block, TxEip1559};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Address, PrimitiveSignature as Signature, TxKind, B256, U256};
    use op_alloy_consensus::{OpTypedTransaction, TxDeposit};
    use reth_chainspec::MAINNET;
    use reth_optimism_chainspec::OpChainSpecBuilder;
    use reth_optimism_primitives::OpTransactionSigned;
    use reth_primitives::Recovered;
    use reth_provider::test_utils::MockEthProvider;
    use reth_transaction_pool::{
        blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder, TransactionOrigin,
        TransactionValidationOutcome,
    };
    use std::sync::Arc;

    #[test]
    fn validate_optimism_transaction() {
        let client = MockEthProvider::<OpTransactionSigned>::default();
        let validator = EthTransactionValidatorBuilder::new(MAINNET.clone())
            .no_shanghai()
            .no_cancun()
            .build(client, InMemoryBlobStore::default());
        let validator = OpTransactionValidator::new(validator);

        let origin = TransactionOrigin::External;
        let signer = Default::default();
        let deposit_tx = OpTypedTransaction::Deposit(TxDeposit {
            source_hash: Default::default(),
            from: signer,
            to: TxKind::Create,
            mint: None,
            value: U256::ZERO,
            gas_limit: 0,
            is_system_transaction: false,
            input: Default::default(),
        });
        let signature = Signature::test_signature();
        let signed_tx = OpTransactionSigned::new_unhashed(deposit_tx, signature);
        let signed_recovered = Recovered::new_unchecked(signed_tx, signer);
        let len = signed_recovered.encode_2718_len();
        let pooled_tx = OpPooledTransaction::new(signed_recovered, len);
        let outcome = validator.validate_one(origin, pooled_tx);

        let err = match outcome {
            TransactionValidationOutcome::Invalid(_, err) => err,
            _ => panic!("Expected invalid transaction"),
        };
        assert_eq!(err.to_string(), "transaction type not supported");
    }

    #[test]
    fn block_fetch_failed_interop() {
        let client = MockEthProvider::<OpTransactionSigned>::default();
        let op_spec = OpChainSpecBuilder::optimism_mainnet().isthmus_activated().build();
        let validator = EthTransactionValidatorBuilder::new(Arc::new(op_spec.inner.clone()))
            .no_shanghai()
            .no_cancun()
            .build(client, InMemoryBlobStore::default());
        let evm_config = OpEvmConfig::new(Arc::new(op_spec));
        let validator = OpTransactionValidator::new(validator).with_evm_config(Some(evm_config));

        let origin = TransactionOrigin::External;
        let signer = Default::default();
        let deposit_tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: 10,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Default::default(),
        });
        let signature = Signature::test_signature();
        let signed_tx = OpTransactionSigned::new_unhashed(deposit_tx, signature);
        let signed_recovered = Recovered::new_unchecked(signed_tx, signer);
        let len = signed_recovered.encode_2718_len();
        let pooled_tx = OpPooledTransaction::new(signed_recovered, len);
        let outcome = validator.validate_one(origin, pooled_tx);

        let err = match outcome {
            TransactionValidationOutcome::Error(_, err) => err,
            _ => panic!("Expected invalid transaction"),
        };
        assert_eq!(err.to_string(), "latest block fetch failed");
    }

    #[test]
    fn validate_optimism_transaction_interop_tx_exec_fails() {
        let client = MockEthProvider::<OpTransactionSigned>::default();
        client.add_block(B256::default(), Block::<OpTransactionSigned>::default());
        let op_spec = OpChainSpecBuilder::optimism_mainnet().isthmus_activated().build();
        let validator = EthTransactionValidatorBuilder::new(Arc::new(op_spec.inner.clone()))
            .no_shanghai()
            .no_cancun()
            .build(client, InMemoryBlobStore::default());
        let evm_config = OpEvmConfig::new(Arc::new(op_spec));
        let validator = OpTransactionValidator::new(validator).with_evm_config(Some(evm_config));

        let origin = TransactionOrigin::External;
        let signer = Default::default();
        let deposit_tx = OpTypedTransaction::Eip1559(TxEip1559 {
            chain_id: 10,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(Address::ZERO),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Default::default(),
        });
        let signature = Signature::test_signature();
        let signed_tx = OpTransactionSigned::new_unhashed(deposit_tx, signature);
        let signed_recovered = Recovered::new_unchecked(signed_tx, signer);
        let len = signed_recovered.encode_2718_len();
        let pooled_tx = OpPooledTransaction::new(signed_recovered, len);
        let outcome = validator.validate_one(origin, pooled_tx);

        let err = match outcome {
            TransactionValidationOutcome::Error(_, err) => err,
            _ => panic!("Expected invalid transaction"),
        };
        assert_eq!(err.to_string(), "transaction execution failed");
    }
}
