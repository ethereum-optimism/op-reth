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
            block: header_storage_root,
            local: storage_root,
        })
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use alloc::sync::Arc;
    use core::str::FromStr;

    use alloy_consensus::Header;
    use alloy_primitives::{keccak256, B256, U256};
    use reth_db_common::init::init_genesis;
    use reth_optimism_chainspec::OpChainSpec;
    use reth_provider::{
        providers::BlockchainProvider2, test_utils::create_test_provider_factory_with_chain_spec,
        StateWriter,
    };
    use reth_trie::{
        test_utils::storage_root_prehashed, HashedPostState, HashedStorage, StorageRoot,
    };
    use reth_trie_db::DatabaseStorageRoot;

    use super::*;

    #[test]
    fn l2tol1_message_passer() {
        let hashed_address = keccak256(ADDRESS_L2_TO_L1_MESSAGE_PASSER);

        // create account storage
        let init_storage = HashedStorage::from_iter(
            false,
            [
                "50000000000000000000000000000004253371b55351a08cb3267d4d265530b6",
                "512428ed685fff57294d1a9cbb147b18ae5db9cf6ae4b312fa1946ba0561882e",
                "51e6784c736ef8548f856909870b38e49ef7a4e3e77e5e945e0d5e6fcaa3037f",
            ]
            .into_iter()
            .map(|str| (B256::from_str(str).unwrap(), U256::from(1))),
        );
        let mut state = HashedPostState::default();
        state.storages.insert(hashed_address, init_storage.clone());

        // init test db
        // note: must be empty (default) chain spec to ensure storage is empty after init genesis,
        // otherwise can't use `storage_root_prehashed` to verify storage root later
        let provider_factory =
            create_test_provider_factory_with_chain_spec(Arc::new(OpChainSpec::default()));
        let _ = init_genesis(&provider_factory).unwrap();

        // write account storage to database
        let provider_rw = provider_factory.provider_rw().unwrap();
        provider_rw.write_hashed_state(&state.clone().into_sorted()).unwrap();
        provider_rw.commit().unwrap();

        // verify db write by loading database storage root
        let provider_rw = provider_factory.provider_rw().unwrap();
        let tx = provider_rw.tx_ref();
        let (storage_root, _, _) =
            StorageRoot::from_tx_hashed(tx, hashed_address).calculate(true).unwrap();
        assert_eq!(storage_root, storage_root_prehashed(init_storage.storage));

        // create block header with withdrawals root set to storage root of l2tol1-msg-passer
        let header = Header { withdrawals_root: Some(storage_root), ..Default::default() };

        // create state provider factory
        drop(provider_rw);
        let state_provider_factory = BlockchainProvider2::new(provider_factory).unwrap();

        // validate block
        validate_l2_to_l1_msg_passer(&state_provider_factory, &header).unwrap();
    }
}
