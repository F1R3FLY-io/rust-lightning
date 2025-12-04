//! A module to provide RGB functionality

#![allow(missing_docs)]

use crate::chain::transaction::OutPoint;
use crate::ln::chan_utils::{
	get_counterparty_payment_script, BuiltCommitmentTransaction, ClosingTransaction,
	CommitmentTransaction, HTLCOutputInCommitment,
};
use crate::ln::channel::{ChannelContext, ChannelError};
use crate::ln::channel_state::ChannelDetails;
use crate::ln::channelmanager::MsgHandleErrInternal;
use crate::ln::features::ChannelTypeFeatures;
use crate::ln::types::{ChannelId, PaymentHash};
use crate::sign::SignerProvider;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hex::DisplayHex;
use bitcoin::hashes::hex::FromHex;
use bitcoin::psbt::{ExtractTxError, Psbt};
use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};
use bitcoin::TxOut;
use hypersonic::ContractId;
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;

use bitcoin::Txid as RgbTxid;

use core::ops::Deref;
use std::collections::HashMap;
use std::fs;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

// TODO: Replace these stubs with F1r3fly implementations
// Temporary stubs for rgb_lib/rgbstd types that we're removing

/// Directory name for RGB channel info files within LDK data directory
pub const RGB_INFO_DIR: &str = "rgb_info";

/// Trait for executing channel settlement operations
///
/// This allows the rgb_utils module to trigger settlement without directly
/// depending on F1r3flyRgbWalletWrapper (avoiding circular dependencies).
pub trait SettlementExecutor: Send + Sync {
	/// Execute channel closing settlement
	///
	/// Returns the state hash for embedding in the closing transaction's OP_RETURN
	fn settle_channel_close(
		&self,
		funding_utxo: &str,
		holder_amount: u64,
		counterparty_amount: u64,
		contract_id: &str,
	) -> Result<[u8; 32], RgbLibError>;

	/// Claim RGB assets from witness ID to Bitcoin UTXO after settlement
	///
	/// This is called immediately after settle_channel_close() to move assets from
	/// F1r3node witness IDs to actual Bitcoin UTXOs (aligning with rgb-lib's atomic behavior).
	///
	/// # Arguments
	/// * `witness_id` - The F1r3node witness ID containing the assets (e.g., "witness:hash:0")
	/// * `destination_utxo` - The Bitcoin UTXO to claim to (e.g., "txid:vout")
	/// * `contract_id` - The RGB contract ID
	///
	/// # Returns
	/// Ok(()) if claim succeeds, Err otherwise
	fn claim_from_witness(
		&self,
		witness_id: &str,
		destination_utxo: &str,
		contract_id: &str,
	) -> Result<(), RgbLibError>;

	/// Check if a witness ID has already been claimed
	///
	/// # Arguments
	/// * `witness_id` - The F1r3node witness ID to check (e.g., "witness:hash:0")
	/// * `contract_id` - The RGB contract ID
	///
	/// # Returns
	/// Ok(true) if witness has been claimed, Ok(false) if not, Err on storage error
	fn is_witness_claimed(
		&self,
		witness_id: &str,
		contract_id: &str,
	) -> Result<bool, RgbLibError>;
}

/// Global reference to the settlement executor (set during wallet initialization)
static SETTLEMENT_EXECUTOR: OnceLock<Arc<dyn SettlementExecutor>> = OnceLock::new();

/// Set the global settlement executor
///
/// This should be called once during wallet initialization
pub fn set_settlement_executor(executor: Arc<dyn SettlementExecutor>) {
	let _ = SETTLEMENT_EXECUTOR.set(executor);
}

/// Trait for reloading contracts manager from disk
///
/// This allows rgb_utils module to trigger a contracts manager reload when
/// external code (e.g., channel acceptor) writes new contract metadata to disk.
pub trait ContractReloader: Send + Sync {
	/// Reload the F1r3fly contracts manager from the state file
	///
	/// This re-initializes the contracts manager to pick up newly written
	/// contract metadata (e.g., when accepting an RGB channel).
	fn reload_contracts(&self) -> Result<(), RgbLibError>;
}

/// Global reference to the contract reloader (set during wallet initialization)
static CONTRACT_RELOADER: OnceLock<Arc<dyn ContractReloader>> = OnceLock::new();

/// Set the global contract reloader
///
/// This should be called once during wallet initialization
pub fn set_contract_reloader(reloader: Arc<dyn ContractReloader>) {
	let _ = CONTRACT_RELOADER.set(reloader);
}

/// RGB transport protocol stub
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum RgbTransport {
	/// JSON-RPC transport
	JsonRpc {
		/// RPC endpoint
		endpoint: String
	},
	/// REST HTTP transport
	RestHttp {
		/// HTTP endpoint
		endpoint: String
	},
}

impl RgbTransport {
	pub fn from_str(s: &str) -> Result<Self, String> {
		if let Some(endpoint) = s.strip_prefix("rpc://") {
			Ok(RgbTransport::JsonRpc { endpoint: endpoint.to_string() })
		} else if let Some(endpoint) = s.strip_prefix("http://") {
			Ok(RgbTransport::RestHttp { endpoint: endpoint.to_string() })
		} else {
			Err("Invalid RGB transport string".to_string())
		}
	}
}

impl fmt::Display for RgbTransport {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			RgbTransport::JsonRpc { endpoint } => write!(f, "rpc://{}", endpoint),
			RgbTransport::RestHttp { endpoint } => write!(f, "http://{}", endpoint),
		}
	}
}

/// RGB asset schema stub
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetSchema {
	/// Non-Inflatable Asset
	Nia,
	/// Unique Digital Asset
	Uda,
	/// Collectible Fungible Asset
	Cfa,
	/// Inflatable Fungible Asset
	Ifa,
}

impl AssetSchema {
	pub fn from_schema_id(_schema_id: String) -> Result<Self, RgbLibError> {
		Ok(AssetSchema::Nia) // Stub: always return NIA
	}
}

impl fmt::Display for AssetSchema {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			AssetSchema::Nia => write!(f, "NIA"),
			AssetSchema::Uda => write!(f, "UDA"),
			AssetSchema::Cfa => write!(f, "CFA"),
			AssetSchema::Ifa => write!(f, "IFA"),
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Assignment {
	Fungible(u64),
	NonFungible,
	Any,
	InflationRight(u64),
	ReplaceRight,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
	Mainnet,
	Testnet,
	Testnet4,
	Signet,
	Regtest,
}

impl BitcoinNetwork {
	pub fn from_str(s: &str) -> Result<Self, String> {
		match s {
			"mainnet" => Ok(BitcoinNetwork::Mainnet),
			"testnet" => Ok(BitcoinNetwork::Testnet),
			"testnet4" => Ok(BitcoinNetwork::Testnet4),
			"signet" => Ok(BitcoinNetwork::Signet),
			"regtest" => Ok(BitcoinNetwork::Regtest),
			_ => Err(format!("Invalid bitcoin network: {}", s)),
		}
	}
}

impl std::str::FromStr for BitcoinNetwork {
	type Err = String;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Self::from_str(s)
	}
}

impl fmt::Display for BitcoinNetwork {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			BitcoinNetwork::Mainnet => write!(f, "mainnet"),
			BitcoinNetwork::Testnet => write!(f, "testnet"),
			BitcoinNetwork::Testnet4 => write!(f, "testnet4"),
			BitcoinNetwork::Signet => write!(f, "signet"),
			BitcoinNetwork::Regtest => write!(f, "regtest"),
		}
	}
}

impl From<BitcoinNetwork> for bitcoin::Network {
	fn from(network: BitcoinNetwork) -> Self {
		match network {
			BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
			BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
			BitcoinNetwork::Testnet4 => bitcoin::Network::Testnet4,
			BitcoinNetwork::Signet => bitcoin::Network::Signet,
			BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
		}
	}
}

#[derive(Debug)]
pub enum RgbLibError {
	InvalidConsignment,
	NoConsignment,
	UnknownRgbSchema { schema_id: String },
	UnsupportedSchema { asset_schema: AssetSchema },
	AllocationsAlreadyAvailable,
	AssetNotFound,
	BatchTransferNotFound,
	CannotEstimateFees,
	CannotFailBatchTransfer,
	EmptyFile,
	FailedBdkSync { details: String },
	FailedBroadcast { details: String },
	FailedIssuance { details: String },
	Inconsistency { details: String },
	Indexer { details: String },
	InsufficientAllocationSlots,
	InsufficientAssignments,
	InsufficientBitcoins { needed: u64, available: u64 },
	InvalidAddress { details: String },
	InvalidAmountZero,
	InvalidAssetID { asset_id: String },
	InvalidAssignment,
	InvalidAttachments { details: String },
	InvalidDetails { details: String },
	InvalidElectrum { details: String },
	InvalidEstimationBlocks,
	InvalidFeeRate { details: String },
	InvalidFilePath,
	InvalidIndexer { details: String },
	InvalidInvoice { details: String },
	InvalidName { details: String },
	InvalidPrecision { details: String },
	InvalidProxyProtocol { version: String },
	InvalidRecipientData { details: String },
	InvalidRecipientID,
	InvalidRecipientNetwork,
	InvalidTicker { details: String },
	InvalidTransportEndpoint { details: String },
	InvalidTransportEndpoints { details: String },
	MaxFeeExceeded { txid: String },
	MinFeeNotMet { txid: String },
	Network { details: String },
	NoIssuanceAmounts,
	NoValidTransportEndpoint,
	OutputBelowDustLimit,
	Proxy { details: String },
	RecipientIDAlreadyUsed,
	TooHighIssuanceAmounts,
	UnsupportedLayer1 { layer_1: String },
	UnsupportedTransportType,
	IO { details: String },
	Other(String),
}

impl std::fmt::Display for RgbLibError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{:?}", self)
	}
}

impl std::error::Error for RgbLibError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessOrd {
	Ignored,
	OffChain,
	OnChain(u64),
	Tentative,
}

// Stub for rgb_lib Wallet (to be replaced with F1r3fly implementation)
pub struct Wallet {
	ldk_data_dir: PathBuf,
}

impl Wallet {
	pub fn new(wallet_data: wallet::WalletData) -> Result<Self, RgbLibError> {
		// Store the ldk_data_dir for later use
		let ldk_data_dir = wallet_data.data_dir.join(".ldk");
		Ok(Wallet { ldk_data_dir })
	}

	pub fn go_online(&self, _online: bool, _indexer_url: String) -> Result<Online, RgbLibError> {
		Ok(Online)
	}

	pub fn accept_transfer(
		&self,
		funding_txid: String,
		_funding_vout: u32,
		consignment_endpoint: Option<RgbTransport>,
		_static_blinding: u64,
	) -> Result<(RgbTransfer, Vec<Assignment>), RgbLibError> {
		// For F1r3fly: Download JSON with contract_id + state_hash instead of consignment
		eprintln!("📥 accept_transfer CALLED: funding_txid={}, endpoint={:?}", funding_txid, consignment_endpoint);

		let endpoint = consignment_endpoint
			.ok_or(RgbLibError::NoConsignment)?;
		eprintln!("📥 accept_transfer: endpoint resolved: {}", endpoint);

		// For F1r3fly: use funding_txid as the recipient_id
		// This matches how Node1 posts the consignment with the funding TXID as the recipient
		let recipient_id = &funding_txid;

		// GET consignment from proxy using JSON-RPC
		let endpoint_str = endpoint.to_string();
		let base_url = if endpoint_str.starts_with("rpc://") {
			endpoint_str.replacen("rpc://", "http://", 1)
		} else if endpoint_str.starts_with("rpcs://") {
			endpoint_str.replacen("rpcs://", "https://", 1)
		} else {
			endpoint_str.clone()
		};

		// Create JSON-RPC request
		let rpc_request = serde_json::json!({
			"method": "consignment.get",
			"jsonrpc": "2.0",
			"id": "1",
			"params": {
				"recipient_id": recipient_id
			}
		});

		eprintln!("📥 accept_transfer: Sending JSON-RPC GET to {}", base_url);
		eprintln!("📥 accept_transfer: Request: {:?}", rpc_request);

		let client = reqwest::blocking::Client::new();
		let response = client.post(base_url)
			.header("Content-Type", "application/json")
			.json(&rpc_request)
			.send()
			.map_err(|e| {
				eprintln!("❌ accept_transfer: HTTP request failed: {}", e);
				RgbLibError::Other(format!("Failed to get channel info: {}", e))
			})?;

		eprintln!("📥 accept_transfer: Response status: {}", response.status());

		if !response.status().is_success() {
			return Err(RgbLibError::NoConsignment);
		}

		// Parse JSON-RPC response
		#[derive(serde::Deserialize)]
		struct JsonRpcResponse {
			result: Option<JsonRpcResult>,
			error: Option<serde_json::Value>,
		}

		#[derive(serde::Deserialize)]
		struct JsonRpcResult {
			consignment: String,
		}

		let rpc_response = response.json::<JsonRpcResponse>()
			.map_err(|e| {
				eprintln!("❌ accept_transfer: Failed to parse JSON-RPC response: {}", e);
				RgbLibError::Other(format!("Failed to parse JSON-RPC response: {}", e))
			})?;

		eprintln!("📥 accept_transfer: Parsed JSON-RPC response successfully");

		if let Some(error) = rpc_response.error {
			eprintln!("❌ accept_transfer: JSON-RPC error: {}", error);
			return Err(RgbLibError::Other(format!("JSON-RPC error: {}", error)));
		}

		let result = rpc_response.result
			.ok_or_else(|| {
				eprintln!("❌ accept_transfer: No result in JSON-RPC response");
				RgbLibError::NoConsignment
			})?;

		eprintln!("📥 accept_transfer: Got result from JSON-RPC response");

		// The "consignment" field contains base64-encoded F1r3fly JSON data
		// (proxy stores all consignments as base64)
		let consignment_b64 = result.consignment;
		eprintln!("📥 accept_transfer: Consignment data (base64) length: {} bytes", consignment_b64.len());

		use base64::Engine;
		let json_bytes = base64::engine::general_purpose::STANDARD.decode(&consignment_b64)
			.map_err(|e| {
				eprintln!("❌ accept_transfer: Failed to decode base64: {}", e);
				RgbLibError::Other(format!("Failed to decode base64 consignment: {}", e))
			})?;

		let json_text = String::from_utf8(json_bytes)
			.map_err(|e| {
				eprintln!("❌ accept_transfer: Failed to convert to UTF-8: {}", e);
				RgbLibError::Other(format!("Failed to convert consignment to UTF-8: {}", e))
			})?;

		eprintln!("📥 accept_transfer: Decoded JSON length: {} bytes", json_text.len());

		#[derive(serde::Deserialize)]
		struct F1r3flyChannelInfo {
			contract_id: String,
			genesis_state_hash: String,
			asset_amount: u64,
			schema: String,
			// Full contract metadata for Node2 registration
			ticker: String,
			name: String,
			precision: u8,
			supply: u64,
			registry_uri: String,
			rholang_source: String,
			methods: Vec<String>,
			// Counterparty's wallet public key for witness ownership (Phase 3)
			wallet_pubkey: String,
		}

		let channel_info: F1r3flyChannelInfo = serde_json::from_str(&json_text)
			.map_err(|e| {
				eprintln!("❌ accept_transfer: Failed to parse F1r3flyChannelInfo: {}", e);
				eprintln!("❌ accept_transfer: JSON text was: {}", json_text);
				RgbLibError::InvalidConsignment
			})?;

		eprintln!("📥 accept_transfer: Parsed F1r3flyChannelInfo successfully");
		eprintln!("  Contract: {} ({})", channel_info.ticker, channel_info.name);
		eprintln!("  Supply: {}, Precision: {}", channel_info.supply, channel_info.precision);

		// Parse schema
		let schema = match channel_info.schema.as_str() {
			"Nia" => AssetSchema::Nia,
			"Uda" => AssetSchema::Uda,
			"Cfa" => AssetSchema::Cfa,
			"Ifa" => AssetSchema::Ifa,
			_ => return Err(RgbLibError::Other(format!("Unknown schema: {}", channel_info.schema))),
		};

		// Write Node2's f1r3fly_state.json and register contract in contracts manager
		write_acceptor_state_file(
			&self.ldk_data_dir,
			&channel_info.contract_id,
			&channel_info.genesis_state_hash,
			&channel_info.ticker,
			&channel_info.name,
			channel_info.precision,
			channel_info.supply,
			&channel_info.registry_uri,
			&channel_info.rholang_source,
			&channel_info.methods,
			&channel_info.wallet_pubkey,  // Phase 3: Pass counterparty's wallet pubkey
		)?;

		// Phase 7: Post Node2's wallet pubkey back to proxy for Node1 to retrieve
		// This enables bidirectional public key exchange
		post_acceptor_pubkey_after_accept(
			&self.ldk_data_dir,
			&channel_info.contract_id,
			&endpoint_str,
		)?;

		// Parse contract_id
		let contract_id = ContractId::from_str(&channel_info.contract_id)
			.map_err(|e| RgbLibError::Other(format!("Invalid contract_id: {}", e)))?;

		// Return in rgb-lib compatible format
		let assignment = match schema {
			AssetSchema::Nia | AssetSchema::Cfa => Assignment::Fungible(channel_info.asset_amount),
			AssetSchema::Uda => Assignment::NonFungible,
			AssetSchema::Ifa => todo!(),
		};

		let transfer = RgbTransfer::new(contract_id, schema);
		Ok((transfer, vec![assignment]))
	}

	/// Find RgbInfo for a channel by contract ID
	///
	/// Scans .pending files in ldk_data_dir to find the channel with this contract_id.
	/// This is necessary because color_psbt() doesn't receive the channel_id parameter.
	///
	/// Returns (RgbInfo, channel_id_hex) on success.
	fn find_rgb_info_by_contract(
		&self,
		contract_id: &ContractId,
	) -> Result<(RgbInfo, String), RgbLibError> {
		// Scan ldk_data_dir for .pending files
		let ldk_dir = &self.ldk_data_dir;

		let entries = fs::read_dir(ldk_dir)
			.map_err(|e| RgbLibError::Other(format!("Failed to read ldk_data_dir: {}", e)))?;

		for entry in entries {
			let entry = entry.map_err(|e| RgbLibError::Other(format!("Failed to read dir entry: {}", e)))?;
			let path = entry.path();

			// Check if this is a .pending file
			if path.extension().and_then(|s| s.to_str()) == Some("pending") {
				// Try to parse as RgbInfo
				if let Ok(rgb_info) = fs::read_to_string(&path)
					.and_then(|content| serde_json::from_str::<RgbInfo>(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
				{
					// Check if this channel has our contract
					if rgb_info.contract_id == *contract_id {
						// Found it! Extract channel_id from filename
						let channel_id_hex = path.file_stem()
							.and_then(|s| s.to_str())
							.ok_or(RgbLibError::Other("Invalid filename".to_string()))?
							.to_string();

						eprintln!("✅ find_rgb_info_by_contract: Found RgbInfo for contract {}", contract_id);
						eprintln!("  Channel ID: {}", channel_id_hex);
						eprintln!("  local_rgb_amount: {}", rgb_info.local_rgb_amount);
						eprintln!("  remote_rgb_amount: {}", rgb_info.remote_rgb_amount);

						return Ok((rgb_info, channel_id_hex));
					}
				}
			}
		}

		Err(RgbLibError::Other(format!(
			"No RgbInfo file found for contract {}",
			contract_id
		)))
	}

	pub fn color_psbt(&self, psbt: &mut Psbt, coloring_info: ColoringInfo) -> Result<(Fascia, FileContent), RgbLibError> {
		eprintln!("🎨 color_psbt: ENTRY");
		eprintln!("  INPUT psbt.unsigned_tx.output.len() = {}", psbt.unsigned_tx.output.len());
		eprintln!("  INPUT psbt.outputs.len() = {}", psbt.outputs.len());
		eprintln!("  INPUT psbt.inputs.len() = {}", psbt.inputs.len());
		eprintln!("  INPUT psbt.unsigned_tx.input.len() = {}", psbt.unsigned_tx.input.len());
		eprintln!("  INPUT psbt.unsigned_tx.version = {}", psbt.unsigned_tx.version.0);
		eprintln!("  INPUT psbt.unsigned_tx.lock_time = {}", psbt.unsigned_tx.lock_time.to_consensus_u32());

		for (i, out) in psbt.unsigned_tx.output.iter().enumerate() {
			if out.script_pubkey.is_op_return() {
				eprintln!("  INPUT Output {}: OP_RETURN ({} bytes)", i, out.script_pubkey.len());
			} else {
				eprintln!("  INPUT Output {}: {} sats, script: {}", i, out.value.to_sat(), out.script_pubkey.len());
			}
		}

		for (i, input) in psbt.inputs.iter().enumerate() {
			eprintln!("  INPUT PSBT Input {}: witness_utxo={}, non_witness_utxo={}, final_script_witness={}",
				i,
				input.witness_utxo.is_some(),
				input.non_witness_utxo.is_some(),
				input.final_script_witness.is_some()
			);
		}

		for (i, output) in psbt.outputs.iter().enumerate() {
			eprintln!("  INPUT PSBT Output {}: redeem_script={}, witness_script={}, bip32_derivation={}",
				i,
				output.redeem_script.is_some(),
				output.witness_script.is_some(),
				output.bip32_derivation.len()
			);
		}

		// 1. Get contract ID and asset info
		let (contract_id, asset_info) = coloring_info
			.asset_info_map
			.iter()
			.next()
			.ok_or(RgbLibError::Other("No RGB asset info in coloring_info".to_string()))?;

		// 2. Detect transaction type and get appropriate state hash
		// CRITICAL: F1r3fly needs different behavior for closing TXs vs commitment/HTLC TXs
		// - Closing TX: Execute settle_channel() on F1r3node to split assets atomically
		// - Commitment/HTLC: Assets stay in funding UTXO, use genesis state hash

	eprintln!("🔍 color_psbt: Transaction type = {:?}", coloring_info.ln_tx_type);
	eprintln!("  total_outputs (TX) = {}", psbt.unsigned_tx.output.len());
	eprintln!("  output_map.len() (RGB) = {}", asset_info.output_map.len());
	eprintln!("  nonce = {:?}", coloring_info.nonce);

	let is_closing_tx = matches!(coloring_info.ln_tx_type, LnTransactionType::Closing);

	let state_hash = if is_closing_tx {
		eprintln!("🔚 color_psbt: CLOSING TRANSACTION - executing settlement");

		// Extract funding UTXO from closing transaction's input
		// The closing TX spends the funding UTXO, so input[0] is the funding outpoint
		let funding_outpoint = psbt.unsigned_tx.input.get(0)
			.ok_or(RgbLibError::Other("Closing TX has no inputs".to_string()))?
			.previous_output;

		let funding_txid = funding_outpoint.txid.to_string();
		let funding_vout = funding_outpoint.vout;

		// CRITICAL: Use "witness:txid:vout" format to match send_end() and settle_channel_close()
		// This must be identical to what send_end() used during channel opening transfer
		// so that the witness ID generation (sha256(funding_witness_id + "holder")) produces the same result
		let funding_utxo = format!("{}:{}", funding_txid, funding_vout);
		let funding_witness_id = format!("witness:{}", funding_utxo);

		eprintln!("  Funding outpoint: {}:{}", funding_txid, funding_vout);
		eprintln!("  Funding UTXO: {}", funding_utxo);
		eprintln!("  Funding witness ID (for F1r3node): {}", funding_witness_id);

			// Read RgbInfo to get the correct holder and counterparty amounts
			// This is the ONLY correct source of truth for final channel balances
			// Aligned with rgb-lib approach (see color_closing lines 484-485 in original)
			//
			// Why we need RgbInfo:
			// - output_map only tells us vout indices and amounts
			// - We cannot determine which vout is holder vs counterparty from vout order alone
			// - RgbInfo.local_rgb_amount and remote_rgb_amount are the authoritative source
			let (rgb_info, channel_id_hex) = self.find_rgb_info_by_contract(contract_id)?;

			let holder_amount = rgb_info.local_rgb_amount;
			let counterparty_amount = rgb_info.remote_rgb_amount;

			let contract_id_str = contract_id.to_string();
			eprintln!("  Contract ID: {}", contract_id_str);
			eprintln!("  Channel ID: {}", channel_id_hex);
			eprintln!("  Holder amount (local): {}", holder_amount);
			eprintln!("  Counterparty amount (remote): {}", counterparty_amount);

		// Execute settlement on F1r3node
		// NOTE: Pass plain funding_utxo (not witness ID) as this is the API parameter
		// The execute_settlement -> settle_channel_close will add "witness:" prefix internally
		eprintln!("🔄 color_psbt: Calling execute_settlement()...");
		let settlement_hash = self.execute_settlement(&funding_utxo, holder_amount, counterparty_amount, &contract_id_str)?;

			// ============================================================================
			// AUTO-CLAIM: Move assets from witness IDs to closing TX outputs
			// ============================================================================
			//
			// RGB-lib behavior: color_psbt() atomically transfers assets from funding UTXO
			// to closing TX outputs via a single RGB state transition.
			//
			// F1r3fly behavior: We need two steps:
			// 1. settle_channel() - distributes assets to witness IDs
			// 2. claim() - moves assets from witness IDs to Bitcoin UTXOs
			//
			// We do step 2 immediately after step 1 to mimic rgb-lib's atomicity.
			//
		eprintln!("🎯 color_psbt: AUTO-CLAIM phase starting...");

		// Generate holder witness ID (MUST match settle_channel_close pattern exactly)
		// CRITICAL: Use funding_witness_id ("witness:txid:vout") to match settle_channel_close()
		use bitcoin::hashes::{Hash, sha256};
		let holder_hash = sha256::Hash::hash(
			format!("{}holder", funding_witness_id).as_bytes()
		);
		let holder_hash_hex = format!("{}", holder_hash);
		let holder_witness = format!("witness:{}:0", &holder_hash_hex[0..32]);

		eprintln!("  Holder witness ID: {}", holder_witness);

			// Determine destination UTXO for claim: closing TX's to_holder output
			// We need to find the vout for the holder's output in the closing transaction
			if holder_amount > 0 {
				// Find the holder's output vout from output_map
				let holder_vout = asset_info.output_map.iter()
					.find(|(_, &amount)| amount == holder_amount)
					.map(|(&vout, _)| vout)
					.ok_or(RgbLibError::Other(format!(
						"Could not find holder output in output_map (holder_amount={})",
						holder_amount
					)))?;

				// Build destination UTXO string
				// Note: We use a placeholder txid since the closing TX hasn't been broadcast yet
				// F1r3fly should handle pending/future UTXOs in its claim() implementation
				let closing_txid = psbt.unsigned_tx.compute_txid();
				let destination_utxo = format!("{}:{}", closing_txid, holder_vout);

				eprintln!("  Destination UTXO: {}", destination_utxo);
				eprintln!("  Holder amount: {}", holder_amount);

				// IDEMPOTENCY CHECK: Skip claim if this witness has already been claimed
				// The Rholang claim() method transfers the ENTIRE witness balance on first call,
				// so subsequent calls will fail. We check claim_storage to avoid duplicate claims.
				let executor = SETTLEMENT_EXECUTOR
					.get()
					.ok_or(RgbLibError::Other("Settlement executor not initialized".to_string()))?;

				let already_claimed = executor.is_witness_claimed(&holder_witness, &contract_id_str)?;

				if already_claimed {
					eprintln!("⏭️  color_psbt: Witness {} already claimed, skipping duplicate", holder_witness);
				} else {
					// Execute claim via settlement executor
					eprintln!("🔄 color_psbt: Calling claim_from_witness()...");

					executor.claim_from_witness(&holder_witness, &destination_utxo, &contract_id_str)
						.map_err(|e| {
							eprintln!("❌ color_psbt: Auto-claim failed: {}", e);
							e
						})?;

					eprintln!("✅ color_psbt: Auto-claim successful - assets now in closing TX output");
				}
			} else {
				eprintln!("⚠️  color_psbt: Holder amount is 0, skipping auto-claim");
			}

			settlement_hash
		} else {
			eprintln!("📝 color_psbt: COMMITMENT/HTLC transaction - using genesis state hash");
			// Commitment or HTLC transaction - use genesis state hash
			// Assets stay in funding UTXO, only Lightning state changes
			self.get_f1r3fly_state_hash(contract_id)?
		};

	// 3. Find or add the OP_RETURN output
	let opreturn_index = match psbt.unsigned_tx.output
		.iter()
		.position(|o| o.script_pubkey.is_op_return())
	{
		Some(idx) => {
			eprintln!("  OP_RETURN found at existing index: {}", idx);
			idx
		}
		None => {
			// No OP_RETURN yet (commitment/closing TX created by LDK)
			// Add it now
			eprintln!("  ⚠️  No OP_RETURN found, adding new output");
			let opreturn_output = TxOut {
				value: bitcoin::Amount::ZERO,
				script_pubkey: bitcoin::ScriptBuf::new_op_return(&[]),
			};
			psbt.unsigned_tx.output.push(opreturn_output);
			// Also resize psbt.outputs to match
			psbt.outputs.resize(psbt.unsigned_tx.output.len(), Default::default());
			let idx = psbt.unsigned_tx.output.len() - 1;
			eprintln!("  Added OP_RETURN at new index: {}", idx);
			idx
		}
	};

	eprintln!("  State hash (32 bytes): {:02x?}", &state_hash[..]);

	// 4. Update the OP_RETURN script with actual state hash
	let opreturn_script = bitcoin::ScriptBuf::new_op_return(&state_hash);

	// 5. Update PSBT in-place
	psbt.unsigned_tx.output[opreturn_index].script_pubkey = opreturn_script.clone();

	eprintln!("  ✅ Successfully updated OP_RETURN at index {}", opreturn_index);

	// 6. Log final PSBT state
	eprintln!("🎨 color_psbt: AFTER MODIFICATION");
	eprintln!("  OUTPUT psbt.unsigned_tx.output.len() = {}", psbt.unsigned_tx.output.len());
	eprintln!("  OUTPUT psbt.outputs.len() = {}", psbt.outputs.len());
	for (i, out) in psbt.unsigned_tx.output.iter().enumerate() {
		if out.script_pubkey.is_op_return() {
			let opret_data = if out.script_pubkey.len() > 2 {
				&out.script_pubkey.as_bytes()[2..] // Skip OP_RETURN and length byte
			} else {
				&[]
			};
			eprintln!("  OUTPUT Output {}: OP_RETURN with {} bytes of data", i, opret_data.len());
		} else {
			eprintln!("  OUTPUT Output {}: {} sats", i, out.value.to_sat());
		}
	}

	// 7. Verify PSBT can be extracted
	let extract_result = psbt.clone().extract_tx();
	match extract_result {
		Ok(tx) => {
			eprintln!("  ✅ PSBT extraction: SUCCESS");
			eprintln!("  Extracted TXID: {}", tx.compute_txid());
		}
		Err(e) => {
			eprintln!("  ❌ PSBT extraction: FAILED - {:?}", e);
		}
	}

		// 8. Return Fascia (stub for now - we don't use consignments in F1r3fly)
		let fascia = Fascia;
		let file_content = FileContent;

		Ok((fascia, file_content))
	}

	pub fn consume_fascia(&self, _fascia: Fascia, _txid: RgbTxid, _witness_ord: Option<WitnessOrd>) -> Result<(), RgbLibError> {
		// Stub: always succeed
		// F1r3fly doesn't use consignments - state is managed on F1r3node
		// The commitment TX already embeds the state hash in OP_RETURN
		Ok(())
	}

	/// Post acceptor's wallet public key to proxy (Phase 7)
	///
	/// After Node2 accepts a channel, it posts its wallet public key back to the proxy
	/// so Node1 can retrieve it when closing the channel.
	///
	/// Uses recipient_id format: "{contract_id}_acceptor_pubkey"
	pub fn post_acceptor_pubkey_to_proxy(
		&self,
		contract_id: &str,
		wallet_pubkey: &str,
		proxy_url: &str,
	) -> Result<(), RgbLibError> {
		eprintln!("📤 post_acceptor_pubkey_to_proxy: Posting Node2's pubkey to proxy");
		eprintln!("   Contract: {}", contract_id);
		eprintln!("   Pubkey: {}", wallet_pubkey);

		// Create recipient_id for acceptor's pubkey
		let recipient_id = format!("{}_acceptor_pubkey", contract_id);

		// Create JSON payload with just the pubkey
		let payload = serde_json::json!({
			"wallet_pubkey": wallet_pubkey,
			"contract_id": contract_id,
		});

		let json_body = serde_json::to_string(&payload)
			.map_err(|e| RgbLibError::Other(format!("JSON serialization failed: {}", e)))?;

		// Convert proxy_url from rpc:// to http:// scheme
		let http_proxy_url = if proxy_url.starts_with("rpc://") {
			proxy_url.replacen("rpc://", "http://", 1)
		} else if proxy_url.starts_with("rpcs://") {
			proxy_url.replacen("rpcs://", "https://", 1)
		} else {
			proxy_url.to_string()
		};

		// Create JSON-RPC params
		let params_json = serde_json::json!({
			"recipient_id": recipient_id,
		});
		let params_str = serde_json::to_string(&params_json)
			.map_err(|e| RgbLibError::Other(format!("Failed to serialize params: {}", e)))?;

		// Encode JSON as base64 (matching consignment format)
		use base64::Engine;
		let json_b64 = base64::engine::general_purpose::STANDARD.encode(json_body.as_bytes());

		// Create JSON-RPC request with base64-encoded "file" content
		let rpc_request = serde_json::json!({
			"method": "consignment.post",
			"jsonrpc": "2.0",
			"id": "1",
			"params": {
				"recipient_id": recipient_id,
				"consignment": json_b64,  // Proxy expects base64 in "consignment" field
			}
		});

		eprintln!("📤 post_acceptor_pubkey_to_proxy: Sending to {}", http_proxy_url);

		let client = reqwest::blocking::Client::new();
		let response = client.post(&http_proxy_url)
			.header("Content-Type", "application/json")
			.json(&rpc_request)
			.send()
			.map_err(|e| RgbLibError::Other(format!("Failed to post acceptor pubkey: {}", e)))?;

		if !response.status().is_success() {
			eprintln!("⚠️  post_acceptor_pubkey_to_proxy: Proxy POST failed: {}", response.status());
			return Err(RgbLibError::Other(format!(
				"Proxy rejected acceptor pubkey post: {}",
				response.status()
			)));
		}

		eprintln!("✅ post_acceptor_pubkey_to_proxy: Acceptor pubkey posted successfully");
		Ok(())
	}

	/// Get counterparty's wallet public key with cache + proxy fallback (Phase 7)
	///
	/// First checks the local cache (channel_counterparties in f1r3fly_state.json).
	/// If not found, downloads from proxy using recipient_id: "{contract_id}_acceptor_pubkey"
	/// and caches it for future use.
	pub fn get_counterparty_pubkey(
		&self,
		contract_id: &str,
		proxy_url: &str,
	) -> Result<String, RgbLibError> {
		eprintln!("🔍 get_counterparty_pubkey: Looking up counterparty for contract {}", contract_id);

		// Path: ldk_data_dir/../rgb-lightning-wallet/f1r3fly_state.json
		let wallet_dir = self.ldk_data_dir
			.parent()
			.ok_or(RgbLibError::Other("Cannot get parent directory".to_string()))?
			.join("rgb-lightning-wallet");
		let state_file_path = wallet_dir.join("f1r3fly_state.json");

		// Try cache first
		if state_file_path.exists() {
			let state_json = fs::read_to_string(&state_file_path)
				.map_err(|e| RgbLibError::Other(format!("Failed to read state file: {}", e)))?;

			let state: serde_json::Value = serde_json::from_str(&state_json)
				.map_err(|e| RgbLibError::Other(format!("Failed to parse state JSON: {}", e)))?;

			if let Some(counterparty_pubkey) = state
				.get("channel_counterparties")
				.and_then(|cp| cp.get(contract_id))
				.and_then(|v| v.as_str())
			{
				eprintln!("✅ get_counterparty_pubkey: Found in cache: {}", counterparty_pubkey);
				return Ok(counterparty_pubkey.to_string());
			}
		}

		eprintln!("📥 get_counterparty_pubkey: Not in cache, fetching from proxy...");

		// Not in cache - fetch from proxy
		let recipient_id = format!("{}_acceptor_pubkey", contract_id);

		// Convert proxy_url from rpc:// to http:// scheme
		let http_proxy_url = if proxy_url.starts_with("rpc://") {
			proxy_url.replacen("rpc://", "http://", 1)
		} else if proxy_url.starts_with("rpcs://") {
			proxy_url.replacen("rpcs://", "https://", 1)
		} else {
			proxy_url.to_string()
		};

		// Create JSON-RPC GET request
		let rpc_request = serde_json::json!({
			"method": "consignment.get",
			"jsonrpc": "2.0",
			"id": "1",
			"params": {
				"recipient_id": recipient_id
			}
		});

		let client = reqwest::blocking::Client::new();
		let response = client.post(&http_proxy_url)
			.header("Content-Type", "application/json")
			.json(&rpc_request)
			.send()
			.map_err(|e| RgbLibError::Other(format!("Failed to get counterparty pubkey: {}", e)))?;

		if !response.status().is_success() {
			return Err(RgbLibError::Other(format!(
				"Proxy GET failed for acceptor pubkey: {}",
				response.status()
			)));
		}

		// Parse JSON-RPC response
		#[derive(serde::Deserialize)]
		struct JsonRpcResponse {
			result: Option<JsonRpcResult>,
			error: Option<serde_json::Value>,
		}

		#[derive(serde::Deserialize)]
		struct JsonRpcResult {
			consignment: String,
		}

		let rpc_response = response.json::<JsonRpcResponse>()
			.map_err(|e| RgbLibError::Other(format!("Failed to parse response: {}", e)))?;

		if let Some(error) = rpc_response.error {
			return Err(RgbLibError::Other(format!("Proxy error: {}", error)));
		}

		let result = rpc_response.result
			.ok_or_else(|| RgbLibError::Other("No result in response".to_string()))?;

		// Decode base64 consignment
		use base64::Engine;
		let json_bytes = base64::engine::general_purpose::STANDARD.decode(&result.consignment)
			.map_err(|e| RgbLibError::Other(format!("Failed to decode base64: {}", e)))?;

		let json_text = String::from_utf8(json_bytes)
			.map_err(|e| RgbLibError::Other(format!("Failed to convert to UTF-8: {}", e)))?;

		// Parse pubkey payload
		#[derive(serde::Deserialize)]
		struct PubkeyPayload {
			wallet_pubkey: String,
		}

		let payload: PubkeyPayload = serde_json::from_str(&json_text)
			.map_err(|e| RgbLibError::Other(format!("Failed to parse pubkey payload: {}", e)))?;

		let counterparty_pubkey = payload.wallet_pubkey;
		eprintln!("✅ get_counterparty_pubkey: Retrieved from proxy: {}", counterparty_pubkey);

		// Cache it for future use
		if state_file_path.exists() {
			let mut state: serde_json::Value = serde_json::from_str(
				&fs::read_to_string(&state_file_path)
					.map_err(|e| RgbLibError::Other(format!("Failed to read state: {}", e)))?
			).unwrap_or(serde_json::json!({}));

			if state.get("channel_counterparties").is_none() {
				state["channel_counterparties"] = serde_json::json!({});
			}
			state["channel_counterparties"][contract_id] = serde_json::json!(counterparty_pubkey);

			let json_str = serde_json::to_string_pretty(&state)
				.map_err(|e| RgbLibError::Other(format!("Failed to serialize: {}", e)))?;

			fs::write(&state_file_path, &json_str)
				.map_err(|e| RgbLibError::Other(format!("Failed to write state: {}", e)))?;

			eprintln!("💾 get_counterparty_pubkey: Cached for future use");
		}

		Ok(counterparty_pubkey)
	}

	/// Read funding UTXO from f1r3fly_state.json
	///
	/// The funding UTXO is stored in the contract's data when the RGB channel is opened.
	/// It's used as the source UTXO for channel closing settlement.
	fn read_funding_utxo_from_state(&self, contract_id_str: &str) -> Result<String, RgbLibError> {
		let state_file_path = self.ldk_data_dir
			.parent()
			.ok_or(RgbLibError::Other("Cannot get parent directory".to_string()))?
			.join("rgb-lightning-wallet")
			.join("f1r3fly_state.json");

		let state_json = fs::read_to_string(&state_file_path)
			.map_err(|e| RgbLibError::Other(format!("Failed to read state file: {}", e)))?;

		let state: serde_json::Value = serde_json::from_str(&state_json)
			.map_err(|e| RgbLibError::Other(format!("Failed to parse state JSON: {}", e)))?;

		let contract_data = state
			.get("genesis_utxos")
			.and_then(|c| c.get(contract_id_str))
			.ok_or(RgbLibError::Other(format!("Contract {} not found in state (genesis_utxos)", contract_id_str)))?;

		// The funding UTXO is stored as "txid:vout" in the genesis UTXO data
		let txid = contract_data
			.get("txid")
			.and_then(|t| t.as_str())
			.ok_or(RgbLibError::Other(format!("TXID not found for contract {}", contract_id_str)))?;

		let vout = contract_data
			.get("vout")
			.and_then(|v| v.as_u64())
			.ok_or(RgbLibError::Other(format!("Vout not found for contract {}", contract_id_str)))?;

		Ok(format!("{}:{}", txid, vout))
	}

	/// Execute channel closing settlement
	///
	/// Calls the global SettlementExecutor to perform atomic settlement on F1r3node.
	/// Returns the new state hash for embedding in the closing transaction's OP_RETURN.
	fn execute_settlement(
		&self,
		funding_utxo: &str,
		holder_amount: u64,
		counterparty_amount: u64,
		contract_id: &str,
	) -> Result<[u8; 32], RgbLibError> {
		let executor = SETTLEMENT_EXECUTOR
			.get()
			.ok_or(RgbLibError::Other("Settlement executor not initialized".to_string()))?;

		executor.settle_channel_close(funding_utxo, holder_amount, counterparty_amount, contract_id)
	}

	/// Get F1r3fly state hash for a contract
	///
	/// This is used to embed the current RGB state into commitment transactions
	/// via OP_RETURN outputs.
	/// Get F1r3fly state hash for commitment transaction coloring
	///
	/// For commitment transactions, we use the genesis state hash from the asset's
	/// initial issuance. This is correct because:
	/// 1. Commitment TXs are never broadcast (just bilateral agreements)
	/// 2. F1r3node state doesn't change during channel lifetime (funding UTXO unchanged)
	/// 3. State hash proves the channel has authentic RGB assets
	/// 4. Real state update only happens on channel close (settlement TX)
	///
	/// The genesis state hash is read from f1r3fly_state.json in the parent directory
	/// of ldk_data_dir (where the F1r3fly wallet stores its state).
	fn get_f1r3fly_state_hash(&self, contract_id: &ContractId) -> Result<[u8; 32], RgbLibError> {
		// Path to f1r3fly_state.json: parent directory of .ldk/ + wallet subdirectory
		// The wallet is stored in: parent_dir/rgb-lightning-wallet/f1r3fly_state.json
		let state_file_path = self.ldk_data_dir
			.parent()
			.ok_or(RgbLibError::Other("Cannot get parent directory".to_string()))?
			.join("rgb-lightning-wallet")
			.join("f1r3fly_state.json");

		eprintln!("📖 get_f1r3fly_state_hash: Looking for contract_id={} in {}", contract_id, state_file_path.display());

		if !state_file_path.exists() {
			eprintln!("❌ get_f1r3fly_state_hash: File does not exist!");
			return Err(RgbLibError::Other(format!(
				"F1r3fly state file not found: {}",
				state_file_path.display()
			)));
		}

		// Read and parse the state file
		let state_json = fs::read_to_string(&state_file_path)
			.map_err(|e| RgbLibError::Other(format!("Failed to read state file: {}", e)))?;

		let state: serde_json::Value = serde_json::from_str(&state_json)
			.map_err(|e| RgbLibError::Other(format!("Failed to parse state JSON: {}", e)))?;

		// Look up the contract in the genesis_utxos map
		// F1r3fly stores contract data under "genesis_utxos" key
		let contract_id_str = contract_id.to_string();

		let contract_data = state
			.get("genesis_utxos")
			.and_then(|c| c.get(&contract_id_str))
			.ok_or(RgbLibError::Other(format!(
				"Contract {} not found in state (genesis_utxos)",
				contract_id_str
			)))?;

	// Extract state hash
	// For Node2 (acceptor), state_hash is stored at top level (genesis_execution_result is null)
	// For Node1 (issuer), state_hash is in genesis_execution_result.state_hash
	// Try top level first (Node2 case), then fall back to nested (Node1 case)
	let state_hash_array = contract_data
		.get("state_hash")
		.and_then(|h| h.as_array())
		.or_else(|| {
			contract_data
				.get("genesis_execution_result")
				.and_then(|g| g.get("state_hash"))
				.and_then(|h| h.as_array())
		})
		.ok_or(RgbLibError::Other(format!(
			"Genesis state hash not found for contract {}",
			contract_id_str
		)))?;

	eprintln!("📖 get_f1r3fly_state_hash: Found state_hash array with {} elements", state_hash_array.len());

	// Convert JSON array to [u8; 32]
	if state_hash_array.len() != 32 {
		return Err(RgbLibError::Other(format!(
			"Invalid state hash length: expected 32 bytes, got {}",
			state_hash_array.len()
		)));
	}

	let mut state_hash = [0u8; 32];
	for (i, byte_val) in state_hash_array.iter().enumerate() {
		state_hash[i] = byte_val.as_u64()
			.ok_or(RgbLibError::Other(format!("Invalid byte at index {}", i)))? as u8;
	}

		Ok(state_hash)
	}

	// Stub methods for src/rgb.rs and src/ldk.rs
	pub fn blind_receive(&self, _asset_id: Option<String>, _assignment: Assignment, _duration_seconds: Option<u32>, _transport_endpoints: Vec<String>, _min_confirmations: u8) -> Result<ReceiveData, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn color_psbt_and_consume(&self, _psbt: &mut Psbt, _coloring_info: ColoringInfo) -> Result<Vec<RgbTransfer>, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn create_utxos(&self, _online: Online, _up_to: bool, _num: Option<u8>, _size: Option<u32>, _fee_rate: u64, _skip_sync: bool) -> Result<u8, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn fail_transfers(&self, _online: Online, _batch_transfer_idx: Option<i32>, _no_asset_only: bool, _skip_sync: bool) -> Result<bool, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn get_address(&self) -> Result<String, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn get_asset_balance(&self, _asset_id: String) -> Result<Balance, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn get_asset_metadata(&self, _asset_id: String) -> Result<Metadata, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn get_btc_balance(&self, _online: Option<Online>, _skip_sync: bool) -> Result<BtcBalance, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn get_fee_estimation(&self, _online: Online, _blocks: u16) -> Result<f64, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn get_media_dir(&self) -> std::path::PathBuf {
		std::path::PathBuf::new()
	}

	pub fn get_send_consignment_path(&self, _asset_id: &str, _txid: &str) -> std::path::PathBuf {
		std::path::PathBuf::new()
	}

	pub fn get_tx_height(&self, _txid: String) -> Result<Option<u32>, RgbLibError> {
		Ok(None)
	}

	pub fn get_wallet_data(&self) -> wallet::WalletData {
		unimplemented!()
	}

	pub fn issue_asset_cfa(&self, _name: String, _description: Option<String>, _precision: u8, _amounts: Vec<u64>, _file_path: Option<String>) -> Result<AssetCFA, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn issue_asset_nia(&self, _ticker: String, _name: String, _precision: u8, _amounts: Vec<u64>) -> Result<AssetNIA, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn issue_asset_uda(&self, _ticker: String, _name: String, _details: Option<String>, _precision: u8, _media_file_path: Option<String>, _attachments_file_paths: Vec<String>) -> Result<AssetUDA, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn list_assets(&self, _filter_asset_schemas: Vec<AssetSchema>) -> Result<Assets, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn list_transactions(&self, _online: Option<Online>, _skip_sync: bool) -> Result<Vec<RgbLibTransaction>, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn list_transfers(&self, _asset_id: Option<String>) -> Result<Vec<Transfer>, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn list_unspents(&self, _online: Option<Online>, _settled_only: bool, _skip_sync: bool) -> Result<Vec<Unspent>, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn list_unspents_vanilla(&self, _online: Online, _min_confirmations: u8, _skip_sync: bool) -> Result<Vec<Unspent>, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn post_consignment<P: AsRef<std::path::Path>>(&self, _proxy_url: String, _recipient_id: String, _consignment_path: P, _txid: String, _vout: Option<u32>) -> Result<(), RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn refresh(&self, _online: Online, _asset_id: Option<String>, _filter: Vec<String>, _skip_sync: bool) -> Result<RefreshResult, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn save_new_asset(&self, _consignment: RgbTransfer, _txid: String) -> Result<(), RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn send(&self, _online: Online, _recipient_map: std::collections::HashMap<String, Vec<Recipient>>, _donation: bool, _fee_rate: u64, _min_confirmations: u8, _skip_sync: bool) -> Result<OperationResult, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn send_begin(&self, _online: Online, _recipient_map: std::collections::HashMap<String, Vec<Recipient>>, _donation: bool, _fee_rate: u64, _min_confirmations: u8) -> Result<String, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn send_btc(&self, _online: Online, _address: String, _amount: u64, _fee_rate: u64, _skip_sync: bool) -> Result<String, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn send_btc_begin(&self, _online: Online, _address: String, _amount: u64, _fee_rate: u64, _skip_sync: bool) -> Result<String, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn send_btc_end(&self, _online: Online, _signed_psbt: String, _skip_sync: bool) -> Result<String, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn send_end(&self, _online: Online, _signed_psbt: String, _skip_sync: bool) -> Result<OperationResult, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn sign_psbt(&self, _unsigned_psbt: String, _sign_options: Option<SignOptions>) -> Result<String, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn sync(&self, _online: Online) -> Result<(), RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn update_witnesses(&self, _after_height: u32, _force_witnesses: Vec<bitcoin::Txid>) -> Result<UpdateRes, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn upsert_witness(&self, _witness_id: bitcoin::Txid, _witness_ord: WitnessOrd) -> Result<(), RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn witness_receive(&self, _asset_id: Option<String>, _assignment: Assignment, _duration_seconds: Option<u32>, _transport_endpoints: Vec<String>, _min_confirmations: u8) -> Result<ReceiveData, RgbLibError> {
		Err(RgbLibError::Other("Not implemented".to_string()))
	}
}

pub type RgbLibPsbt = Psbt;

// Stubs for rgbstd types
pub trait ConsignmentExt {}

#[derive(Debug, Clone)]
pub struct FileContent;

#[derive(Debug, Clone)]
pub struct Fascia;

#[derive(Debug, Clone)]
pub struct RgbTransfer {
	contract_id: ContractId,
	schema: AssetSchema,
}

impl RgbTransfer {
	pub fn new(contract_id: ContractId, schema: AssetSchema) -> Self {
		Self { contract_id, schema }
	}

	pub fn save_file(&self, _path: &std::path::Path) -> Result<(), std::io::Error> {
		// Stub: always succeed (F1r3fly doesn't use consignment files)
		Ok(())
	}

	pub fn load_file(_path: std::path::PathBuf) -> Result<Self, RgbLibError> {
		// Stub: F1r3fly doesn't load consignments from files
		Err(RgbLibError::Other("Not implemented".to_string()))
	}

	pub fn contract_id(&self) -> ContractId {
		self.contract_id
	}

	pub fn schema_id(&self) -> String {
		match self.schema {
			AssetSchema::Nia => "nia".to_string(),
			AssetSchema::Uda => "uda".to_string(),
			AssetSchema::Cfa => "cfa".to_string(),
			AssetSchema::Ifa => "ifa".to_string(),
		}
	}

	pub fn asset_schema(&self) -> AssetSchema {
		self.schema
	}
}

// Additional wallet-related stub types needed by rgb.rs and routes.rs
#[derive(Debug, Clone)]
pub struct AssetCFA {
	pub asset_id: String,
	pub added_at: i64,
	pub balance: Balance,
	pub details: Option<String>,
	pub issued_supply: u64,
	pub ticker: String,
	pub name: String,
	pub precision: u8,
	pub timestamp: i64,
	pub media: Option<Media>,
}

#[derive(Debug, Clone)]
pub struct AssetNIA {
	pub asset_id: String,
	pub added_at: i64,
	pub balance: Balance,
	pub details: Option<String>,
	pub issued_supply: u64,
	pub ticker: String,
	pub name: String,
	pub precision: u8,
	pub timestamp: i64,
	pub media: Option<Media>,
}

#[derive(Debug, Clone)]
pub struct AssetUDA {
	pub asset_id: String,
	pub added_at: i64,
	pub balance: Balance,
	pub details: Option<String>,
	pub media_idx: Option<u32>,
	pub ticker: String,
	pub name: String,
	pub precision: u8,
	pub timestamp: i64,
	pub token: Option<TokenLight>,
}

#[derive(Debug, Clone)]
pub struct Assets {
	pub nia: Option<Vec<AssetNIA>>,
	pub cfa: Option<Vec<AssetCFA>>,
	pub uda: Option<Vec<AssetUDA>>,
}

#[derive(Debug, Clone, Copy)]
pub struct Balance {
	pub settled: u64,
	pub future: u64,
	pub spendable: u64,
}

#[derive(Debug, Clone)]
pub struct BtcBalance {
	pub vanilla: Balance,
	pub colored: Balance,
}

#[derive(Debug, Clone)]
pub struct Metadata {
	pub asset_iface: String,
	pub asset_schema: AssetSchema,
	pub issued_supply: u64,
	pub timestamp: i64,
	pub name: String,
	pub precision: u8,
	pub ticker: Option<String>,
	pub details: Option<String>,
	pub initial_supply: u64,
	pub max_supply: u64,
	pub known_circulating_supply: u64,
	pub token: Option<Token>,
}

#[derive(Debug, Clone)]
pub struct Online;

#[derive(Debug, Clone)]
pub struct OperationResult {
	pub txid: String,
}

#[derive(Debug, Clone)]
pub struct SignOptions;

#[derive(Debug, Clone)]
pub struct ReceiveData {
	pub recipient_id: String,
	pub invoice: String,
	pub expiration_timestamp: Option<i64>,
	pub batch_transfer_idx: i32,
}

#[derive(Debug, Clone)]
pub struct Recipient {
	pub recipient_id: String,
	pub witness_data: Option<WitnessData>,
	pub assignment: Assignment,
	pub transport_endpoints: Vec<String>,
}

impl Recipient {
	pub fn new(recipient_id: String, witness_data: Option<WitnessData>, assignment: Assignment, transport_endpoints: Vec<String>) -> Self {
		Self { recipient_id, witness_data, assignment, transport_endpoints }
	}
}

#[derive(Debug, Clone)]
pub struct RecipientInfo {
	pub recipient_id: String,
	pub recipient_type: RecipientType,
	pub asset_schema: Option<AssetSchema>,
	pub asset_id: Option<String>,
	pub assignment: Assignment,
	pub network: BitcoinNetwork,
	pub expiration_timestamp: Option<i64>,
	pub transport_endpoints: Vec<String>,
}

impl RecipientInfo {
	pub fn new(recipient_id: String) -> Result<Self, RgbLibError> {
		Ok(Self {
			recipient_id,
			recipient_type: RecipientType::Blind,
			asset_schema: None,
			asset_id: None,
			assignment: Assignment::Any,
			network: BitcoinNetwork::Regtest,
			expiration_timestamp: None,
			transport_endpoints: vec![],
		})
	}
}

#[derive(Debug, Clone)]
pub struct RefreshResult {
	pub new: Vec<String>,
	pub updated: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EmbeddedMedia {
	pub ty: String,
	pub data: Vec<u8>,
	pub mime: String,
}

#[derive(Debug, Clone)]
pub struct Invoice {
	pub invoice_data: String,
}

impl Invoice {
	pub fn new(invoice_data: String) -> Result<Self, RgbLibError> {
		Ok(Self { invoice_data })
	}

	pub fn invoice_data(&self) -> RecipientInfo {
		RecipientInfo {
			recipient_id: String::new(),
			recipient_type: RecipientType::Blind,
			asset_schema: None,
			asset_id: None,
			assignment: Assignment::Any,
			network: BitcoinNetwork::Regtest,
			expiration_timestamp: None,
			transport_endpoints: vec![],
		}
	}
}

#[derive(Debug, Clone)]
pub struct Media {
	pub digest: String,
	pub mime: String,
	pub file_path: String,
}

#[derive(Debug, Clone)]
pub struct ProofOfReserves {
	pub message: String,
	pub utxos: Vec<String>,
	pub utxo: String,
	pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientType {
	Blind,
	Witness,
}

#[derive(Debug, Clone)]
pub struct Token {
	pub index: u32,
	pub ticker: Option<String>,
	pub name: Option<String>,
	pub details: Option<String>,
	pub embedded_media: Option<EmbeddedMedia>,
	pub media: Option<Media>,
	pub attachments: std::collections::HashMap<u8, Media>,
	pub reserves: Option<ProofOfReserves>,
}

#[derive(Debug, Clone)]
pub struct TokenLight {
	pub index: u32,
	pub ticker: Option<String>,
	pub name: Option<String>,
	pub details: Option<String>,
	pub embedded_media: bool,
	pub media: Option<Media>,
	pub attachments: std::collections::HashMap<u8, Media>,
	pub reserves: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
	RgbSend,
	Drain,
	CreateUtxos,
	User,
}

#[derive(Debug, Clone)]
pub struct ConfirmationTime {
	pub height: u32,
	pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct RgbLibTransaction {
	pub txid: String,
	pub received: u64,
	pub sent: u64,
	pub fee: u64,
	pub confirmation_time: Option<ConfirmationTime>,
	pub transaction_type: TransactionType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKind {
	Issuance,
	ReceiveBlind,
	ReceiveWitness,
	Send,
	Inflation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
	WaitingCounterparty,
	WaitingConfirmations,
	Settled,
	Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
	JsonRpc,
}

#[derive(Debug, Clone)]
pub struct Transfer {
	pub idx: i32,
	pub created_at: i64,
	pub updated_at: i64,
	pub status: TransferStatus,
	pub amount: u64,
	pub kind: TransferKind,
	pub txid: Option<String>,
	pub recipient_id: Option<String>,
	pub receive_utxo: Option<wallet::Outpoint>,
	pub change_utxo: Option<wallet::Outpoint>,
	pub expiration: Option<i64>,
	pub transport_endpoints: Vec<TransportEndpoint>,
	pub asset_spend_status: Vec<u8>,
	pub assignments: Vec<Assignment>,
	pub requested_assignment: Option<Assignment>,
}

#[derive(Debug, Clone)]
pub struct TransportEndpoint {
	pub endpoint: String,
	pub transport_type: TransportType,
	pub used: bool,
}

impl TransportEndpoint {
	pub fn new(endpoint: String) -> Option<Self> {
		Some(Self { endpoint, transport_type: TransportType::JsonRpc, used: false })
	}
}

impl TryFrom<RgbTransport> for TransportEndpoint {
	type Error = std::convert::Infallible;

	fn try_from(transport: RgbTransport) -> Result<Self, Self::Error> {
		// Extract endpoint from RgbTransport (which is just a string wrapper)
		let endpoint = transport.to_string();

		// Determine transport type from the endpoint string
		let transport_type = if endpoint.starts_with("rpc://") || endpoint.starts_with("rpcs://") {
			TransportType::JsonRpc
		} else {
			TransportType::JsonRpc // Default to JsonRpc
		};

		Ok(Self {
			endpoint,
			transport_type,
			used: false,
		})
	}
}

#[derive(Debug, Clone)]
pub struct RgbAllocation {
	pub asset_id: Option<String>,
	pub amount: u64,
	pub assignment: Assignment,
	pub settled: bool,
}

#[derive(Debug, Clone)]
pub struct Unspent {
	pub outpoint: wallet::Outpoint,
	pub txout: bitcoin::TxOut,
	pub rgb_allocations: Vec<RgbAllocation>,
	pub utxo: wallet::Outpoint,
}

#[derive(Debug, Clone)]
pub struct WitnessData {
	pub amount_sat: u64,
	pub blinding: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexerProtocol {
	Electrum,
	Esplora,
}

impl fmt::Display for IndexerProtocol {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			IndexerProtocol::Electrum => write!(f, "electrum"),
			IndexerProtocol::Esplora => write!(f, "esplora"),
		}
	}
}

#[derive(Debug, Clone)]
pub struct UpdateRes {
	pub failed: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LnTransactionType {
	Commitment,
	Htlc,
	Closing,
}

#[derive(Clone)]
pub struct ColoringInfo {
	pub asset_info_map: HashMap<ContractId, AssetColoringInfo>,
	pub static_blinding: Option<u64>,
	pub nonce: Option<u64>,
	pub ln_tx_type: LnTransactionType,
}

pub type OutputMap = HashMap<u32, u64>;

#[derive(Clone)]
pub struct AssetColoringInfo {
	pub output_map: OutputMap,
	pub static_blinding: Option<u64>,
}

pub mod wallet {
	use std::fmt;

	pub enum DatabaseType {
		Sqlite,
	}

	#[derive(Debug, Clone)]
	pub struct Outpoint {
		pub outpoint: OutpointInner,
		pub txid: String,
		pub vout: u32,
		pub btc_amount: u64,
		pub colorable: bool,
	}

	#[derive(Debug, Clone)]
	pub struct OutpointInner {
		pub txid: String,
		pub vout: u32,
	}

	impl std::fmt::Display for OutpointInner {
		fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
			write!(f, "{}:{}", self.txid, self.vout)
		}
	}

	impl std::fmt::Display for Outpoint {
		fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
			write!(f, "{}", self.outpoint)
		}
	}

	pub struct WalletData {
		pub data_dir: std::path::PathBuf,
		pub bitcoin_network: crate::rgb_utils::BitcoinNetwork,
		pub database_type: DatabaseType,
		pub max_allocations_per_utxo: u32,
		pub account_xpub_vanilla: String,
		pub account_xpub_colored: String,
		pub master_fingerprint: String,
		pub mnemonic: String,
		pub vanilla_keychain: Option<String>,
		pub supported_schemas: Vec<crate::rgb_utils::AssetSchema>,
	}

	pub mod rust_only {
		pub use crate::rgb_utils::{AssetColoringInfo, ColoringInfo};
	}
}

// Stub utility functions needed by src/ldk.rs, src/routes.rs, src/rgb.rs
pub fn generate_keys(bitcoin_network: BitcoinNetwork) -> wallet::WalletData {
	// Generate a new BIP39 mnemonic (12 words)
	use bitcoin::bip32::{Xpriv, Xpub, DerivationPath};
	use std::str::FromStr;

	// Generate random entropy for 12-word mnemonic (128 bits = 16 bytes)
	let mut entropy = [0u8; 16];
	use bitcoin::hashes::{Hash, sha256};
	// Use current timestamp as seed for entropy (simple approach for testing)
	let timestamp = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("Time error")
		.as_nanos();
	let hash = sha256::Hash::hash(&timestamp.to_le_bytes());
	entropy.copy_from_slice(&hash.as_byte_array()[..16]);

	// Generate mnemonic from entropy
	let mnemonic = bip39::Mnemonic::from_entropy(&entropy).expect("Failed to generate mnemonic");
	let mnemonic_str = mnemonic.to_string();

	// Convert to seed
	let seed = mnemonic.to_seed("");

	// Create master key
	let network = match bitcoin_network {
		BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
		BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
		BitcoinNetwork::Testnet4 => bitcoin::Network::Testnet,
		BitcoinNetwork::Signet => bitcoin::Network::Signet,
		BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
	};

	let master_xpriv = Xpriv::new_master(network, &seed).expect("Failed to create master key");
	let master_fingerprint = master_xpriv.fingerprint(&bitcoin::secp256k1::Secp256k1::new()).to_string();

	// Derive account keys (m/84'/1'/0' for regtest/testnet, m/84'/0'/0' for mainnet)
	let coin_type = if network == bitcoin::Network::Bitcoin { 0 } else { 1 };
	let vanilla_path = DerivationPath::from_str(&format!("m/84'/{}'/0'", coin_type)).expect("Invalid derivation path");
	let colored_path = DerivationPath::from_str(&format!("m/84'/{}'/1'", coin_type)).expect("Invalid derivation path");

	let account_xpriv_vanilla = master_xpriv.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &vanilla_path).expect("Failed to derive vanilla key");
	let account_xpriv_colored = master_xpriv.derive_priv(&bitcoin::secp256k1::Secp256k1::new(), &colored_path).expect("Failed to derive colored key");

	let secp = bitcoin::secp256k1::Secp256k1::new();
	let account_xpub_vanilla = Xpub::from_priv(&secp, &account_xpriv_vanilla).to_string();
	let account_xpub_colored = Xpub::from_priv(&secp, &account_xpriv_colored).to_string();

	wallet::WalletData {
		data_dir: std::path::PathBuf::new(),
		bitcoin_network,
		database_type: wallet::DatabaseType::Sqlite,
		max_allocations_per_utxo: 1,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		mnemonic: mnemonic_str,
		vanilla_keychain: None,
		supported_schemas: vec![AssetSchema::Nia, AssetSchema::Cfa, AssetSchema::Uda],
	}
}

pub fn get_account_data(_bitcoin_network: BitcoinNetwork, _mnemonic: &str, _colored: bool) -> Result<(String, String, String), RgbLibError> {
	Ok(("derivation_path".to_string(), "xpub".to_string(), "fingerprint".to_string()))
}

pub fn recipient_id_from_script_buf(script: &bitcoin::ScriptBuf, network: BitcoinNetwork) -> String {
	// F1r3fly doesn't use RGB recipient IDs for channel operations
	// For channel funding, we need to preserve the funding address in the recipient_id
	// So we just return the Bitcoin address as the recipient_id
	use bitcoin::Address;

	let bdk_network = match network {
		BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
		BitcoinNetwork::Testnet | BitcoinNetwork::Testnet4 => bitcoin::Network::Testnet,
		BitcoinNetwork::Signet => bitcoin::Network::Signet,
		BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
	};

	// Convert script to address
	Address::from_script(script, bdk_network)
		.map(|addr| addr.to_string())
		.unwrap_or_else(|_| {
			// Fallback: if script can't be converted to address, return a placeholder
			format!("rgb:script:{}", bitcoin::hex::DisplayHex::to_lower_hex_string(script.as_bytes()))
		})
}

pub fn script_buf_from_recipient_id(recipient_id: String) -> Result<bitcoin::ScriptBuf, RgbLibError> {
	// For F1r3fly, recipient_id is just a Bitcoin address (not an RGB recipient ID)
	// Parse the address and extract its script_pubkey
	use bitcoin::Address;

	let addr = Address::from_str(&recipient_id)
		.map_err(|e| RgbLibError::Other(format!("Invalid address in recipient_id: {}", e)))?
		.assume_checked(); // Address was created by us, so network is valid

	Ok(addr.script_pubkey())
}

pub fn check_indexer_url(indexer_url: &str, _bitcoin_network: BitcoinNetwork) -> Result<IndexerProtocol, RgbLibError> {
	// Simple check: if it's a port that looks like electrs, assume Electrum protocol
	// Port 50001 is standard electrs port
	if indexer_url.contains(":50001") || indexer_url.contains("electrum") {
		Ok(IndexerProtocol::Electrum)
	} else {
		// Default to Electrum for now
		Ok(IndexerProtocol::Electrum)
	}
}

pub fn check_proxy_url(proxy_url: &str) -> Result<(), RgbLibError> {
	// Simple validation: check if the URL looks valid
	// For regtest, we expect rpc://127.0.0.1:3000/json-rpc
	// For now, just verify it's not empty and contains a protocol
	if proxy_url.is_empty() {
		return Err(RgbLibError::Other("Proxy URL cannot be empty".to_string()));
	}

	if !proxy_url.contains("://") {
		return Err(RgbLibError::Other("Invalid proxy URL format".to_string()));
	}

	// For F1r3fly, we don't actually need to connect to the RGB proxy
	// since we handle RGB state through F1r3node instead
	// Just validate the format and return Ok
	Ok(())
}

/// Static blinding costant (will be removed in the future)
pub const STATIC_BLINDING: u64 = 777;
/// Name of the file containing the bitcoin network
pub const BITCOIN_NETWORK_FNAME: &str = "bitcoin_network";
/// Name of the file containing the electrum URL
pub const INDEXER_URL_FNAME: &str = "indexer_url";
/// Name of the file containing the wallet fingerprint
pub const WALLET_FINGERPRINT_FNAME: &str = "wallet_fingerprint";
/// Name of the file containing the account-level xPub of the vanilla-side of the wallet
pub const WALLET_ACCOUNT_XPUB_VANILLA_FNAME: &str = "wallet_account_xpub_vanilla";
/// Name of the file containing the account-level xPub of the colored-side of the wallet
pub const WALLET_ACCOUNT_XPUB_COLORED_FNAME: &str = "wallet_account_xpub_colored";
/// Name of the file containing the master fingerprint of the wallet
pub const WALLET_MASTER_FINGERPRINT_FNAME: &str = "wallet_master_fingerprint";
const INBOUND_EXT: &str = "inbound";
const OUTBOUND_EXT: &str = "outbound";

/// RGB channel info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbInfo {
	/// Channel contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// Channel schema
	pub schema: AssetSchema,
	/// Channel RGB local amount
	pub local_rgb_amount: u64,
	/// Channel RGB remote amount
	pub remote_rgb_amount: u64,
}

/// RGB payment info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RgbPaymentInfo {
	/// RGB contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// RGB payment amount
	pub amount: u64,
	/// RGB local amount
	pub local_rgb_amount: u64,
	/// RGB remote amount
	pub remote_rgb_amount: u64,
	/// Whether the RGB amount in route should be overridden
	pub swap_payment: bool,
	/// Whether the payment is inbound
	pub inbound: bool,
}

/// RGB transfer info
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransferInfo {
	/// Transfer contract ID
	#[serde(with = "contract_id_serde")]
	pub contract_id: ContractId,
	/// Transfer RGB amount
	pub rgb_amount: u64,
}

mod contract_id_serde {
	use super::*;
	use serde::{Deserializer, Serializer};
	use std::str::FromStr;

	pub fn serialize<S>(id: &ContractId, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		serializer.serialize_str(&id.to_string())
	}

	pub fn deserialize<'de, D>(deserializer: D) -> Result<ContractId, D::Error>
	where
		D: Deserializer<'de>,
	{
		let s = String::deserialize(deserializer)?;
		ContractId::from_str(&s).map_err(serde::de::Error::custom)
	}
}

fn _get_file_in_parent(ldk_data_dir: &Path, fname: &str) -> PathBuf {
	ldk_data_dir.parent().unwrap().join(fname)
}

fn _read_file_in_parent(ldk_data_dir: &Path, fname: &str) -> String {
	fs::read_to_string(_get_file_in_parent(ldk_data_dir, fname)).unwrap()
}

fn _get_rgb_wallet_dir(ldk_data_dir: &Path) -> PathBuf {
	let fingerprint = _read_file_in_parent(ldk_data_dir, WALLET_FINGERPRINT_FNAME);
	_get_file_in_parent(ldk_data_dir, &fingerprint)
}

fn _get_bitcoin_network(ldk_data_dir: &Path) -> BitcoinNetwork {
	let bitcoin_network = _read_file_in_parent(ldk_data_dir, BITCOIN_NETWORK_FNAME);
	BitcoinNetwork::from_str(&bitcoin_network).unwrap()
}

fn _get_account_xpub_colored(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_ACCOUNT_XPUB_COLORED_FNAME)
}

fn _get_account_xpub_vanilla(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_ACCOUNT_XPUB_VANILLA_FNAME)
}

fn _get_master_fingerprint(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, WALLET_MASTER_FINGERPRINT_FNAME)
}

fn _get_indexer_url(ldk_data_dir: &Path) -> String {
	_read_file_in_parent(ldk_data_dir, INDEXER_URL_FNAME)
}

fn _new_rgb_wallet(
	data_dir: String, bitcoin_network: BitcoinNetwork, account_xpub_vanilla: String,
	account_xpub_colored: String, master_fingerprint: String,
) -> Wallet {
	Wallet::new(wallet::WalletData {
		data_dir: data_dir.into(),
		bitcoin_network,
		database_type: wallet::DatabaseType::Sqlite,
		max_allocations_per_utxo: 1,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
		mnemonic: String::new(),
		vanilla_keychain: None,
		supported_schemas: vec![AssetSchema::Nia, AssetSchema::Cfa, AssetSchema::Uda],
	})
	.expect("valid rgb-lib wallet")
}

fn _get_wallet_data(ldk_data_dir: &Path) -> (String, BitcoinNetwork, String, String, String) {
	let data_dir = ldk_data_dir.parent().unwrap().to_string_lossy().to_string();
	let bitcoin_network = _get_bitcoin_network(ldk_data_dir);
	let account_xpub_vanilla = _get_account_xpub_vanilla(ldk_data_dir);
	let account_xpub_colored = _get_account_xpub_colored(ldk_data_dir);
	let master_fingerprint = _get_master_fingerprint(ldk_data_dir);
	(data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint)
}

async fn _get_rgb_wallet(ldk_data_dir: &Path) -> Wallet {
	let (data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint) =
		_get_wallet_data(ldk_data_dir);
	tokio::task::spawn_blocking(move || {
		_new_rgb_wallet(
			data_dir,
			bitcoin_network,
			account_xpub_vanilla,
			account_xpub_colored,
			master_fingerprint,
		)
	})
	.await
	.unwrap()
}

/// Post Node2's wallet pubkey to proxy after accepting channel (Phase 7 helper)
///
/// Creates a temporary wallet to access the executor and get Node2's wallet master pubkey,
/// then posts it to the proxy for Node1 to retrieve later when closing the channel.
fn post_acceptor_pubkey_after_accept(
	ldk_data_dir: &Path,
	contract_id: &str,
	proxy_url: &str,
) -> Result<(), RgbLibError> {
	eprintln!("📤 post_acceptor_pubkey_after_accept: Posting Node2's pubkey to proxy");

	// Get wallet data to create temporary wallet
	let (data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint) =
		_get_wallet_data(ldk_data_dir);

	// Create temporary wallet to access executor
	let wallet = _new_rgb_wallet(
		data_dir,
		bitcoin_network,
		account_xpub_vanilla,
		account_xpub_colored,
		master_fingerprint,
	);

	// Get Node2's wallet master public key from the executor
	// This requires accessing the F1r3flyRgbWalletWrapper, which we don't have direct access to here
	//
	// WORKAROUND: Read the FIREFLY_PRIVATE_KEY from environment and derive the pubkey
	// This is safe because all nodes on the same wallet use the same master key
	use std::env;
	let master_key_hex = env::var("FIREFLY_PRIVATE_KEY")
		.map_err(|_| RgbLibError::Other("FIREFLY_PRIVATE_KEY not set".to_string()))?;

	let master_key_bytes = hex::decode(&master_key_hex)
		.map_err(|e| RgbLibError::Other(format!("Invalid master key hex: {}", e)))?;

	let master_secret_key = SecretKey::from_slice(&master_key_bytes)
		.map_err(|e| RgbLibError::Other(format!("Invalid secp256k1 master key: {}", e)))?;

	let secp = Secp256k1::new();
	let master_public_key = PublicKey::from_secret_key(&secp, &master_secret_key);
	let wallet_pubkey = hex::encode(master_public_key.serialize_uncompressed());

	eprintln!("   Node2 wallet pubkey: {}", wallet_pubkey);

	// Create recipient_id for acceptor's pubkey
	let recipient_id = format!("{}_acceptor_pubkey", contract_id);

	// Create JSON payload
	let payload = serde_json::json!({
		"wallet_pubkey": wallet_pubkey,
		"contract_id": contract_id,
	});

	let json_body = serde_json::to_string(&payload)
		.map_err(|e| RgbLibError::Other(format!("JSON serialization failed: {}", e)))?;

	// Convert proxy_url from rpc:// to http:// scheme
	let http_proxy_url = if proxy_url.starts_with("rpc://") {
		proxy_url.replacen("rpc://", "http://", 1)
	} else if proxy_url.starts_with("rpcs://") {
		proxy_url.replacen("rpcs://", "https://", 1)
	} else {
		proxy_url.to_string()
	};

	// Create JSON-RPC params
	// Note: Proxy requires txid even for non-UTXO data like pubkey exchange
	// We use the recipient_id (which already contains contract_id) as a placeholder txid
	let params_json = serde_json::json!({
		"recipient_id": recipient_id,
		"txid": recipient_id  // Placeholder - proxy requires this field
	});
	let params_str = serde_json::to_string(&params_json)
		.map_err(|e| RgbLibError::Other(format!("Failed to serialize params: {}", e)))?;

	// Write JSON to a temporary file (proxy expects file upload, not text)
	let temp_file_path = ldk_data_dir.join(format!("temp_acceptor_pubkey_{}.json", contract_id));
	fs::write(&temp_file_path, json_body.clone())
		.map_err(|e| RgbLibError::Other(format!("Failed to write temp file: {}", e)))?;

	// Create multipart form with JSON-RPC fields and file (matching post_consignment pattern)
	let form = reqwest::blocking::multipart::Form::new()
		.text("method", "consignment.post")
		.text("jsonrpc", "2.0")
		.text("id", "1")
		.text("params", params_str)
		.file("file", &temp_file_path)
		.map_err(|e| RgbLibError::Other(format!("Failed to attach file: {}", e)))?;

	eprintln!("📤 post_acceptor_pubkey_after_accept: Sending to {}", http_proxy_url);
	eprintln!("   Recipient ID: {}", recipient_id);

	let client = reqwest::blocking::Client::new();
	let response = client.post(&http_proxy_url)
		.multipart(form)
		.send()
		.map_err(|e| RgbLibError::Other(format!("Failed to post acceptor pubkey: {}", e)))?;

	// Clean up temp file
	let _ = fs::remove_file(&temp_file_path);

	if !response.status().is_success() {
		eprintln!("⚠️  post_acceptor_pubkey_after_accept: Proxy POST failed: {}", response.status());
		// Don't fail the channel opening if pubkey posting fails - it's a fallback mechanism
		// Node1 can still get the pubkey via other means if needed
		return Ok(());
	}

	// Parse JSON-RPC response to check for errors
	#[derive(serde::Deserialize)]
	struct JsonRpcResponse {
		result: Option<bool>,
		error: Option<JsonRpcError>,
	}

	#[derive(serde::Deserialize)]
	struct JsonRpcError {
		code: i32,
		message: String,
	}

	let rpc_response: JsonRpcResponse = response.json()
		.map_err(|e| RgbLibError::Other(format!("Failed to parse response: {}", e)))?;

	if let Some(error) = rpc_response.error {
		eprintln!("⚠️  post_acceptor_pubkey_after_accept: Proxy error: {} ({})", error.message, error.code);
		// Don't fail channel opening on pubkey post errors
		return Ok(());
	}

	eprintln!("✅ post_acceptor_pubkey_after_accept: Node2's pubkey posted successfully");
	Ok(())
}

async fn _accept_transfer(
	ldk_data_dir: &Path, funding_txid: String, consignment_endpoint: RgbTransport,
) -> Result<(RgbTransfer, Vec<Assignment>), RgbLibError> {
	// For F1r3fly: Call the wallet's accept_transfer method which will
	// download the JSON and write the state file
	let funding_vout = 1;
	let (data_dir, bitcoin_network, account_xpub_vanilla, account_xpub_colored, master_fingerprint) =
		_get_wallet_data(ldk_data_dir);
	let indexer_url = _get_indexer_url(ldk_data_dir);
	tokio::task::spawn_blocking(move || {
		let mut wallet = _new_rgb_wallet(
			data_dir,
			bitcoin_network,
			account_xpub_vanilla,
			account_xpub_colored,
			master_fingerprint,
		);
		wallet.go_online(true, indexer_url).unwrap();
		wallet.accept_transfer(
			funding_txid.clone(),
			funding_vout,
			Some(consignment_endpoint),
			STATIC_BLINDING,
		)
	})
	.await
	.unwrap()
}

/// Write f1r3fly_state.json for Node2 (acceptor) and register contract
///
/// This function:
/// 1. Writes minimal state to f1r3fly_state.json for transaction coloring
/// 2. Registers the contract with F1r3flyContractsManager for balance queries
fn write_acceptor_state_file(
	ldk_data_dir: &Path,
	contract_id: &str,
	genesis_state_hash: &str,
	ticker: &str,
	name: &str,
	precision: u8,
	supply: u64,
	registry_uri: &str,
	rholang_source: &str,
	methods: &[String],
	counterparty_wallet_pubkey: &str,  // Phase 4: Counterparty's wallet public key
) -> Result<(), RgbLibError> {
	eprintln!("📝 write_acceptor_state_file: Registering contract for Node2");
	eprintln!("  Contract: {} ({}) - {}", ticker, name, contract_id);

	// Path: ldk_data_dir/../rgb-lightning-wallet/f1r3fly_state.json
	let wallet_dir = ldk_data_dir
		.parent()
		.ok_or(RgbLibError::Other("Cannot get parent directory".to_string()))?
		.join("rgb-lightning-wallet");

	let state_file_path = wallet_dir.join("f1r3fly_state.json");

	// Ensure directory exists
	fs::create_dir_all(&wallet_dir)
		.map_err(|e| RgbLibError::Other(format!("Cannot create directory: {}", e)))?;

	// Read existing state or create new
	let mut state: serde_json::Value = if state_file_path.exists() {
		let content = fs::read_to_string(&state_file_path)
			.map_err(|e| RgbLibError::Other(format!("Failed to read state: {}", e)))?;
		serde_json::from_str(&content)
			.unwrap_or(serde_json::json!({
				"genesis_utxos": {},
				"contracts_metadata": {},
				"contract_derivation_indices": {},
				"derivation_index": 0,
			}))
	} else {
		serde_json::json!({
			"genesis_utxos": {},
			"contracts_metadata": {},
			"contract_derivation_indices": {},
			"derivation_index": 0,
		})
	};

	// Ensure all required keys exist
	if state.get("genesis_utxos").is_none() {
		state["genesis_utxos"] = serde_json::json!({});
	}
	if state.get("contracts_metadata").is_none() {
		state["contracts_metadata"] = serde_json::json!({});
	}

	// Convert hex string state_hash to byte array for JSON
	let state_hash_bytes = hex::decode(genesis_state_hash)
		.map_err(|e| RgbLibError::Other(format!("Invalid hex state hash: {}", e)))?;

	if state_hash_bytes.len() != 32 {
		return Err(RgbLibError::Other(format!(
			"State hash must be 32 bytes, got {}",
			state_hash_bytes.len()
		)));
	}

	// Convert to Vec<u8> for JSON serialization
	let state_hash_array: Vec<u8> = state_hash_bytes;

	// Add genesis UTXO info for balance queries and transaction coloring
	// Node2 (acceptor) doesn't know full genesis execution details (opid, deploy_id, etc.)
	// but DOES know the state_hash (received in channel info JSON payload)
	// Store state_hash at top level for coloring, set genesis_execution_result to null
	state["genesis_utxos"][contract_id] = serde_json::json!({
		"contract_id": contract_id,
		"txid": "unknown",  // Node2 doesn't know actual genesis UTXO (not needed for balance queries)
		"vout": 0,
		"ticker": ticker,
		"name": name,
		"supply": supply,
		"precision": precision,
		"genesis_execution_result": null,  // Node2 doesn't have full genesis execution data
		"state_hash": state_hash_array      // But we DO have the state hash for coloring
	});

	// Add contract metadata for F1r3flyContractsManager registration
	// This enables Node2 to query balances via `/assetbalance`
	state["contracts_metadata"][contract_id] = serde_json::json!({
		"registry_uri": registry_uri,
		"methods": methods,
		"rholang_source": rholang_source,
	});

	// Phase 4: Add channel counterparty tracking
	// Maps contract_id to counterparty's wallet public key
	// This is needed for settle_channel() to register witness ownership correctly
	if state.get("channel_counterparties").is_none() {
		state["channel_counterparties"] = serde_json::json!({});
	}
	state["channel_counterparties"][contract_id] = serde_json::json!(counterparty_wallet_pubkey);

	eprintln!("📝 write_acceptor_state_file: Added channel counterparty for contract {}", contract_id);
	eprintln!("   Counterparty pubkey: {}", counterparty_wallet_pubkey);

	// Write back
	let json_str = serde_json::to_string_pretty(&state)
		.map_err(|e| RgbLibError::Other(format!("Failed to serialize: {}", e)))?;

	eprintln!("📝 write_acceptor_state_file: Writing to {}", state_file_path.display());
	eprintln!("📝 write_acceptor_state_file: contract_id={}, state_hash={}", contract_id, genesis_state_hash);
	eprintln!("📝 write_acceptor_state_file: Added contract metadata: {} methods", methods.len());

	fs::write(&state_file_path, &json_str)
		.map_err(|e| RgbLibError::Other(format!("Failed to write state: {}", e)))?;

	eprintln!("✅ write_acceptor_state_file: File written successfully");
	eprintln!("📝 write_acceptor_state_file: Content:\n{}", json_str);

	// Reload the contracts manager to pick up the newly written contract metadata
	// This is critical for Node2 to be able to query the asset balance
	if let Some(reloader) = CONTRACT_RELOADER.get() {
		eprintln!("🔄 write_acceptor_state_file: Reloading contracts manager...");
		reloader.reload_contracts()?;
		eprintln!("✅ write_acceptor_state_file: Contracts manager reloaded");
	} else {
		eprintln!("⚠️  write_acceptor_state_file: No contract reloader set (test mode?)");
	}

	Ok(())
}

/// Read TransferInfo file
pub fn read_rgb_transfer_info(path: &Path) -> TransferInfo {
	let serialized_info = fs::read_to_string(path).expect("able to read transfer info file");
	serde_json::from_str(&serialized_info).expect("valid transfer info")
}

/// Write TransferInfo file
pub fn write_rgb_transfer_info(path: &PathBuf, info: &TransferInfo) {
	let serialized_info = serde_json::to_string(&info).expect("valid transfer info");
	fs::write(path, serialized_info).expect("able to write transfer info file")
}

fn _counterparty_output_index(
	outputs: &[TxOut], channel_type_features: &ChannelTypeFeatures, payment_key: &PublicKey,
) -> Option<usize> {
	let counterparty_payment_script =
		get_counterparty_payment_script(channel_type_features, payment_key);
	outputs
		.iter()
		.enumerate()
		.find(|(_, out)| out.script_pubkey == counterparty_payment_script)
		.map(|(idx, _)| idx)
}

/// Return the position of the OP_RETURN output, if present
pub fn op_return_position(tx: &Transaction) -> Option<usize> {
	tx.output.iter().position(|o| o.script_pubkey.is_op_return())
}

/// Whether the transaction is colored (i.e. it has an OP_RETURN output)
pub fn is_tx_colored(tx: &Transaction) -> bool {
	op_return_position(tx).is_some()
}

/// Color commitment transaction
pub(crate) fn color_commitment<SP: Deref>(
	channel_context: &ChannelContext<SP>, commitment_transaction: &mut CommitmentTransaction,
	counterparty: bool,
) -> Result<(), ChannelError>
where
	<SP as std::ops::Deref>::Target: SignerProvider,
{
	eprintln!("🎨 color_commitment: START (counterparty={})", counterparty);

	let channel_id = &channel_context.channel_id;
	let funding_outpoint = channel_context.channel_transaction_parameters.funding_outpoint.unwrap();
	let ldk_data_dir = channel_context.ldk_data_dir.as_path();

	let commitment_tx = commitment_transaction.clone().built.transaction;

	let (rgb_info, _) = get_rgb_channel_info_pending(channel_id, ldk_data_dir);
	let contract_id = rgb_info.contract_id;

	let chan_id = channel_id.0.as_hex();
	let mut rgb_offered_htlc = 0;
	let mut rgb_received_htlc = 0;
	let mut last_rgb_payment_info = None;
	let mut output_map = HashMap::new();

	for htlc in commitment_transaction.htlcs() {
		if htlc.rgb_payment.map_or(true, |(_, a)| a == 0) {
			continue;
		}
		let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

		let htlc_vout = htlc.transaction_output_index.unwrap();

		let inbound = htlc.offered == counterparty;

		let htlc_payment_hash = htlc.payment_hash.0.as_hex().to_string();
		let htlc_proxy_id = format!("{chan_id}{htlc_payment_hash}");
		let mut rgb_payment_info_proxy_id_path = ldk_data_dir.join(htlc_proxy_id);
		let rgb_payment_info_path = ldk_data_dir.join(htlc_payment_hash);
		let mut rgb_payment_info_path = rgb_payment_info_path.clone();
		if inbound {
			rgb_payment_info_proxy_id_path.set_extension(INBOUND_EXT);
			rgb_payment_info_path.set_extension(INBOUND_EXT);
		} else {
			rgb_payment_info_proxy_id_path.set_extension(OUTBOUND_EXT);
			rgb_payment_info_path.set_extension(OUTBOUND_EXT);
		}
		let rgb_payment_info_tmp_path = _append_pending_extension(&rgb_payment_info_path);

		if rgb_payment_info_tmp_path.exists() {
			let mut rgb_payment_info = parse_rgb_payment_info(&rgb_payment_info_tmp_path);
			rgb_payment_info.local_rgb_amount = rgb_info.local_rgb_amount;
			rgb_payment_info.remote_rgb_amount = rgb_info.remote_rgb_amount;
			let serialized_info =
				serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
			fs::write(&rgb_payment_info_proxy_id_path, serialized_info)
				.expect("able to write rgb payment info file");
			fs::remove_file(rgb_payment_info_tmp_path).expect("able to remove file");
		}

		let rgb_payment_info = if rgb_payment_info_proxy_id_path.exists() {
			parse_rgb_payment_info(&rgb_payment_info_proxy_id_path)
		} else {
			let rgb_payment_info = RgbPaymentInfo {
				contract_id,
				amount: htlc_amount_rgb,
				local_rgb_amount: rgb_info.local_rgb_amount,
				remote_rgb_amount: rgb_info.remote_rgb_amount,
				swap_payment: true,
				inbound,
			};
			let serialized_info =
				serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
			fs::write(rgb_payment_info_proxy_id_path, serialized_info.clone())
				.expect("able to write rgb payment info file");
			fs::write(rgb_payment_info_path, serialized_info)
				.expect("able to write rgb payment info file");
			rgb_payment_info
		};

		if inbound {
			rgb_received_htlc += rgb_payment_info.amount
		} else {
			rgb_offered_htlc += rgb_payment_info.amount
		};

		output_map.insert(htlc_vout, rgb_payment_info.amount);

		last_rgb_payment_info = Some(rgb_payment_info);
	}

	let (local_amt, remote_amt) = if let Some(last_rgb_payment_info) = last_rgb_payment_info {
		(
			last_rgb_payment_info.local_rgb_amount - rgb_offered_htlc,
			last_rgb_payment_info.remote_rgb_amount - rgb_received_htlc,
		)
	} else {
		(rgb_info.local_rgb_amount, rgb_info.remote_rgb_amount)
	};
	let (vout_p2wpkh_amt, vout_p2wsh_amt) =
		if counterparty { (local_amt, remote_amt) } else { (remote_amt, local_amt) };

	let payment_point = if counterparty {
		channel_context.get_holder_pubkeys().payment_point
	} else {
		channel_context.get_counterparty_pubkeys().payment_point
	};

	if let Some(vout_p2wpkh) = _counterparty_output_index(
		&commitment_tx.output,
		&channel_context.channel_type,
		&payment_point,
	) {
		output_map.insert(vout_p2wpkh as u32, vout_p2wpkh_amt);
	}

	if let Some(vout_p2wsh) = commitment_transaction.trust().revokeable_output_index() {
		output_map.insert(vout_p2wsh as u32, vout_p2wsh_amt);
	}

	let asset_coloring_info =
		AssetColoringInfo { output_map, static_blinding: Some(STATIC_BLINDING) };
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
		ln_tx_type: LnTransactionType::Commitment,
	};
	let psbt = Psbt::from_unsigned_tx(commitment_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info)
		.map_err(|e| {
			eprintln!("❌ color_commitment: Failed to color commitment TX: {}", e);
			ChannelError::Warn(format!("Failed to color commitment TX: {}", e))
		})?;
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = modified_tx.compute_txid();
	commitment_transaction.built = BuiltCommitmentTransaction { transaction: modified_tx, txid };

	wallet
		.consume_fascia(
			fascia.clone(),
			RgbTxid::from_str(&txid.to_string()).unwrap(),
			Some(WitnessOrd::Ignored),
		)
		.unwrap();

	// save RGB transfer data to disk
	let rgb_amount = if counterparty {
		vout_p2wpkh_amt + rgb_offered_htlc
	} else {
		vout_p2wsh_amt + rgb_received_htlc
	};
	let transfer_info = TransferInfo { contract_id, rgb_amount };
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	eprintln!("✅ color_commitment: COMPLETE");
	Ok(())
}

/// Color HTLC transaction
pub(crate) fn color_htlc(
	htlc_tx: &mut Transaction, htlc: &HTLCOutputInCommitment, ldk_data_dir: &Path,
) -> Result<(), ChannelError> {
	if htlc.rgb_payment.map_or(true, |(_, a)| a == 0) {
		return Ok(());
	}
	let (_, htlc_amount_rgb) = htlc.rgb_payment.expect("this HTLC has RGB assets");

	let consignment_htlc_outpoint = htlc_tx.input.first().unwrap().previous_output;
	let commitment_txid = consignment_htlc_outpoint.txid.to_string();

	let transfer_info_path = ldk_data_dir.join(format!("{commitment_txid}_transfer_info"));
	let transfer_info = read_rgb_transfer_info(&transfer_info_path);
	let contract_id = transfer_info.contract_id;

	let asset_coloring_info = AssetColoringInfo {
		output_map: HashMap::from([(0, htlc_amount_rgb)]),
		static_blinding: Some(STATIC_BLINDING),
	};
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: Some(1),
		ln_tx_type: LnTransactionType::Htlc,
	};
	let psbt = Psbt::from_unsigned_tx(htlc_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};
	let txid = &modified_tx.compute_txid();

	wallet
		.consume_fascia(
			fascia.clone(),
			RgbTxid::from_str(&txid.to_string()).unwrap(),
			Some(WitnessOrd::Ignored),
		)
		.unwrap();

	// save RGB transfer data to disk
	let transfer_info = TransferInfo { contract_id, rgb_amount: htlc_amount_rgb };
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Color closing transaction
pub(crate) fn color_closing(
	channel_id: &ChannelId, funding_outpoint: &OutPoint,
	closing_transaction: &mut ClosingTransaction, ldk_data_dir: &Path,
) -> Result<(), ChannelError> {
	let closing_tx = closing_transaction.clone().built;

	let (rgb_info, _) = get_rgb_channel_info_pending(channel_id, ldk_data_dir);
	let contract_id = rgb_info.contract_id;

	let holder_vout_amount = rgb_info.local_rgb_amount;
	let counterparty_vout_amount = rgb_info.remote_rgb_amount;

	let mut output_map = HashMap::new();

	if closing_transaction.to_holder_value_sat() > 0 {
		let holder_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_holder_script())
			.unwrap();
		output_map.insert(holder_vout as u32, holder_vout_amount);
	}

	if closing_transaction.to_counterparty_value_sat() > 0 {
		let counterparty_vout = closing_tx
			.output
			.iter()
			.position(|o| &o.script_pubkey == closing_transaction.to_counterparty_script())
			.unwrap();
		output_map.insert(counterparty_vout as u32, counterparty_vout_amount);
	}

	let asset_coloring_info =
		AssetColoringInfo { output_map, static_blinding: Some(STATIC_BLINDING) };
	let coloring_info = ColoringInfo {
		asset_info_map: HashMap::from_iter([(contract_id, asset_coloring_info)]),
		static_blinding: Some(STATIC_BLINDING),
		nonce: None,
		ln_tx_type: LnTransactionType::Closing,
	};
	let psbt = Psbt::from_unsigned_tx(closing_tx.clone()).unwrap();
	let mut psbt = RgbLibPsbt::from_str(&psbt.to_string()).unwrap();
	let handle = Handle::current();
	let _ = handle.enter();
	let wallet = futures::executor::block_on(_get_rgb_wallet(ldk_data_dir));
	let (fascia, _) = wallet.color_psbt(&mut psbt, coloring_info).unwrap();
	let psbt = Psbt::from_str(&psbt.to_string()).unwrap();
	let modified_tx = match psbt.extract_tx() {
		Ok(tx) => tx,
		Err(ExtractTxError::MissingInputValue { tx }) => tx,
		Err(e) => panic!("should never happen: {e}"),
	};

	let txid = &modified_tx.compute_txid();
	closing_transaction.built = modified_tx;

	wallet
		.consume_fascia(
			fascia.clone(),
			RgbTxid::from_str(&txid.to_string()).unwrap(),
			Some(WitnessOrd::Ignored),
		)
		.unwrap();

	// save RGB transfer data to disk
	let transfer_info = TransferInfo { contract_id, rgb_amount: holder_vout_amount };
	let transfer_info_path = ldk_data_dir.join(format!("{txid}_transfer_info"));
	write_rgb_transfer_info(&transfer_info_path, &transfer_info);

	Ok(())
}

/// Get RgbPaymentInfo file path
pub fn get_rgb_payment_info_path(
	payment_hash: &PaymentHash, ldk_data_dir: &Path, inbound: bool,
) -> PathBuf {
	let mut path = ldk_data_dir.join(payment_hash.0.as_hex().to_string());
	path.set_extension(if inbound { INBOUND_EXT } else { OUTBOUND_EXT });
	path
}

/// Parse RgbPaymentInfo
pub fn parse_rgb_payment_info(rgb_payment_info_path: &PathBuf) -> RgbPaymentInfo {
	let serialized_info =
		fs::read_to_string(rgb_payment_info_path).expect("valid rgb payment info");
	serde_json::from_str(&serialized_info).expect("valid rgb info file")
}

/// Get RgbInfo file path
pub fn get_rgb_channel_info_path(channel_id: &str, ldk_data_dir: &Path, pending: bool) -> PathBuf {
	let mut info_file_path = ldk_data_dir.join(channel_id);
	if pending {
		info_file_path.set_extension("pending");
	}
	info_file_path
}

/// Get RgbInfo file
pub(crate) fn get_rgb_channel_info(
	channel_id: &str, ldk_data_dir: &Path, pending: bool,
) -> (RgbInfo, PathBuf) {
	let info_file_path = get_rgb_channel_info_path(channel_id, ldk_data_dir, pending);
	let info = parse_rgb_channel_info(&info_file_path);
	(info, info_file_path)
}

/// Get pending RgbInfo file
pub fn get_rgb_channel_info_pending(
	channel_id: &ChannelId, ldk_data_dir: &Path,
) -> (RgbInfo, PathBuf) {
	get_rgb_channel_info(&channel_id.0.as_hex().to_string(), ldk_data_dir, true)
}

/// Parse RgbInfo
pub fn parse_rgb_channel_info(rgb_channel_info_path: &PathBuf) -> RgbInfo {
	let serialized_info = fs::read_to_string(rgb_channel_info_path).expect("valid rgb info file");
	serde_json::from_str(&serialized_info).expect("valid rgb info file")
}

/// Whether the channel data for a channel exist
pub fn is_channel_rgb(channel_id: &ChannelId, ldk_data_dir: &Path) -> bool {
	get_rgb_channel_info_path(&channel_id.0.as_hex().to_string(), ldk_data_dir, false).exists()
}

/// Write RgbInfo file
pub fn write_rgb_channel_info(path: &PathBuf, rgb_info: &RgbInfo) {
	let serialized_info = serde_json::to_string(&rgb_info).expect("valid rgb info");
	fs::write(path, serialized_info).expect("able to write")
}

/// Read RgbInfo file for a channel
///
/// Returns None if the file doesn't exist (non-RGB channel) or if parsing fails.
///
/// Aligns with existing `get_rgb_channel_info_path()` - files stored directly in ldk_data_dir
/// as <channel_id_hex> (non-pending) or <channel_id_hex>.pending
pub fn read_rgb_channel_info(channel_id: &ChannelId, ldk_data_dir: &Path) -> Option<RgbInfo> {
	let channel_id_hex = hex::encode(channel_id.0);

	// Try non-pending first (final channel state)
	let info_file_path = get_rgb_channel_info_path(&channel_id_hex, ldk_data_dir, false);

	if !info_file_path.exists() {
		// Try pending (channel still being established)
		let pending_path = get_rgb_channel_info_path(&channel_id_hex, ldk_data_dir, true);
		if !pending_path.exists() {
			return None;
		}
		// Use pending file if non-pending doesn't exist
		return match fs::read_to_string(&pending_path) {
			Ok(contents) => match serde_json::from_str::<RgbInfo>(&contents) {
				Ok(rgb_info) => Some(rgb_info),
				Err(e) => {
					eprintln!("Failed to parse pending RGB info for channel {}: {}", channel_id_hex, e);
					None
				}
			},
			Err(e) => {
				eprintln!("Failed to read pending RGB info for channel {}: {}", channel_id_hex, e);
				None
			}
		};
	}

	// Read non-pending file
	match fs::read_to_string(&info_file_path) {
		Ok(contents) => match serde_json::from_str::<RgbInfo>(&contents) {
			Ok(rgb_info) => Some(rgb_info),
			Err(e) => {
				eprintln!("Failed to parse RGB info file for channel {}: {}", channel_id_hex, e);
				None
			}
		},
		Err(e) => {
			eprintln!("Failed to read RGB info file for channel {}: {}", channel_id_hex, e);
			None
		}
	}
}

fn _append_pending_extension(path: &Path) -> PathBuf {
	let mut new_path = path.to_path_buf();
	new_path.set_extension(format!("{}_pending", new_path.extension().unwrap().to_string_lossy()));
	new_path
}

/// Write RGB payment info to file
pub fn write_rgb_payment_info_file(
	ldk_data_dir: &Path, payment_hash: &PaymentHash, contract_id: ContractId, amount_rgb: u64,
	swap_payment: bool, inbound: bool,
) {
	let rgb_payment_info_path = get_rgb_payment_info_path(payment_hash, ldk_data_dir, inbound);
	let rgb_payment_info_tmp_path = _append_pending_extension(&rgb_payment_info_path);
	let rgb_payment_info = RgbPaymentInfo {
		contract_id,
		amount: amount_rgb,
		local_rgb_amount: 0,
		remote_rgb_amount: 0,
		swap_payment,
		inbound,
	};
	let serialized_info = serde_json::to_string(&rgb_payment_info).expect("valid rgb payment info");
	std::fs::write(rgb_payment_info_path, serialized_info.clone())
		.expect("able to write rgb payment info file");
	std::fs::write(rgb_payment_info_tmp_path, serialized_info)
		.expect("able to write rgb payment info tmp file");
}

/// Rename RGB files from temporary to final channel ID
pub(crate) fn rename_rgb_files(
	channel_id: &ChannelId, temporary_channel_id: &ChannelId, ldk_data_dir: &Path,
) {
	let temp_chan_id = temporary_channel_id.0.as_hex().to_string();
	let chan_id = channel_id.0.as_hex().to_string();

	fs::rename(
		get_rgb_channel_info_path(&temp_chan_id, ldk_data_dir, false),
		get_rgb_channel_info_path(&chan_id, ldk_data_dir, false),
	)
	.expect("rename ok");
	fs::rename(
		get_rgb_channel_info_path(&temp_chan_id, ldk_data_dir, true),
		get_rgb_channel_info_path(&chan_id, ldk_data_dir, true),
	)
	.expect("rename ok");

	let funding_consignment_tmp = ldk_data_dir.join(format!("consignment_{}", temp_chan_id));
	if funding_consignment_tmp.exists() {
		let funding_consignment = ldk_data_dir.join(format!("consignment_{}", chan_id));
		fs::rename(funding_consignment_tmp, funding_consignment).expect("rename ok");
	}
}

/// Handle funding on the receiver side
pub(crate) fn handle_funding(
	temporary_channel_id: &ChannelId, funding_txid: String, ldk_data_dir: &Path,
	consignment_endpoint: RgbTransport,
) -> Result<(), MsgHandleErrInternal> {
	eprintln!("🔧 handle_funding: START (funding_txid={})", funding_txid);
	let handle = Handle::current();
	let _ = handle.enter();
	let accept_res = futures::executor::block_on(_accept_transfer(
		ldk_data_dir,
		funding_txid.clone(),
		consignment_endpoint,
	));
	eprintln!("🔧 handle_funding: accept_transfer returned: {:?}", accept_res.is_ok());
	let (consignment, remote_rgb_assignments) = match accept_res {
		Ok(res) => res,
		Err(RgbLibError::InvalidConsignment) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Invalid RGB consignment for funding".to_owned(),
				*temporary_channel_id,
			))
		},
		Err(RgbLibError::NoConsignment) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				"Failed to find RGB consignment".to_owned(),
				*temporary_channel_id,
			))
		},
		Err(RgbLibError::UnknownRgbSchema { schema_id }) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Unknown RGB schema: {schema_id}"),
				*temporary_channel_id,
			))
		},
		Err(RgbLibError::UnsupportedSchema { asset_schema }) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Unsupported RGB schema: {asset_schema}"),
				*temporary_channel_id,
			))
		},
		Err(e) => {
			return Err(MsgHandleErrInternal::send_err_msg_no_close(
				format!("Unexpected error: {e}"),
				*temporary_channel_id,
			))
		},
	};

	let consignment_path = ldk_data_dir.join(format!("consignment_{}", funding_txid));
	consignment.save_file(&consignment_path).expect("unable to write file");
	let consignment_path =
		ldk_data_dir.join(format!("consignment_{}", temporary_channel_id.0.as_hex()));
	consignment.save_file(&consignment_path).expect("unable to write file");

	if remote_rgb_assignments.len() != 1 {
		return Err(MsgHandleErrInternal::send_err_msg_no_close(
			format!("Unexpected number of RGB assignments: {}", remote_rgb_assignments.len()),
			*temporary_channel_id,
		));
	}
	let remote_rgb_amount = match remote_rgb_assignments[0] {
		Assignment::Fungible(amt) => amt,
		Assignment::NonFungible => 1,
		_ => unreachable!("unsupported schema"),
	};
	let rgb_info = RgbInfo {
		contract_id: consignment.contract_id(),
		schema: consignment.asset_schema(),
		local_rgb_amount: 0,
		remote_rgb_amount,
	};
	let temporary_channel_id_str = temporary_channel_id.0.as_hex().to_string();
	write_rgb_channel_info(
		&get_rgb_channel_info_path(&temporary_channel_id_str, ldk_data_dir, true),
		&rgb_info,
	);
	write_rgb_channel_info(
		&get_rgb_channel_info_path(&temporary_channel_id_str, ldk_data_dir, false),
		&rgb_info,
	);

	eprintln!("✅ handle_funding: SUCCESS - RGB info written for contract_id={}", rgb_info.contract_id);
	Ok(())
}

/// Update RGB channel amount
pub fn update_rgb_channel_amount(
	channel_id: &str, rgb_offered_htlc: u64, rgb_received_htlc: u64, ldk_data_dir: &Path,
	pending: bool,
) {
	let (mut rgb_info, info_file_path) = get_rgb_channel_info(channel_id, ldk_data_dir, pending);

	if rgb_offered_htlc > rgb_received_htlc {
		let spent = rgb_offered_htlc - rgb_received_htlc;
		rgb_info.local_rgb_amount -= spent;
		rgb_info.remote_rgb_amount += spent;
	} else {
		let received = rgb_received_htlc - rgb_offered_htlc;
		rgb_info.local_rgb_amount += received;
		rgb_info.remote_rgb_amount -= received;
	}

	write_rgb_channel_info(&info_file_path, &rgb_info)
}

/// Update pending RGB channel amount
pub(crate) fn update_rgb_channel_amount_pending(
	channel_id: &ChannelId, rgb_offered_htlc: u64, rgb_received_htlc: u64, ldk_data_dir: &Path,
) {
	update_rgb_channel_amount(
		&channel_id.0.as_hex().to_string(),
		rgb_offered_htlc,
		rgb_received_htlc,
		ldk_data_dir,
		true,
	)
}

/// Whether the payment is colored
pub(crate) fn is_payment_rgb(ldk_data_dir: &Path, payment_hash: &PaymentHash) -> bool {
	get_rgb_payment_info_path(payment_hash, ldk_data_dir, false).exists()
		|| get_rgb_payment_info_path(payment_hash, ldk_data_dir, true).exists()
}

/// Detect the contract ID of the payment and then filter hops based on contract ID and amount
pub(crate) fn filter_first_hops(
	ldk_data_dir: &Path, payment_hash: &PaymentHash, first_hops: &mut Vec<ChannelDetails>,
) -> (ContractId, u64) {
	let rgb_payment_info_path = get_rgb_payment_info_path(payment_hash, ldk_data_dir, false);
	let rgb_payment_info = parse_rgb_payment_info(&rgb_payment_info_path);
	let contract_id = rgb_payment_info.contract_id;
	let rgb_amount = rgb_payment_info.amount;
	first_hops.retain(|h| {
		let info_file_path = ldk_data_dir.join(h.channel_id.0.as_hex().to_string());
		if !info_file_path.exists() {
			return false;
		}
		let serialized_info = fs::read_to_string(info_file_path).expect("valid rgb info file");
		let rgb_info: RgbInfo =
			serde_json::from_str(&serialized_info).expect("valid rgb info file");
		rgb_info.contract_id == contract_id && rgb_info.local_rgb_amount >= rgb_amount
	});
	(contract_id, rgb_amount)
}
