//! Addresses of OP pre-deploys.
// todo: move to op-alloy

use alloy_primitives::{address, Address};

/// The L2 contract `L2ToL1MessagePasser`, stores commitments to withdrawal transactions.
pub const ADDRESS_L2_TO_L1_MESSAGE_PASSER: Address =
    address!("C0D3C0d3C0d3c0d3C0d3C0D3c0D3c0d3c0D30016");
