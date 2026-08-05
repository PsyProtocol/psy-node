use std::{collections::BTreeMap, str::FromStr};

use clap::{Parser, command};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parth_core::{pgoldilocks::PoseidonHasher, protocol::core_types::{QHashBase, QNetworkHashTypes}};
use psy_api_core::coordinator::standard_edge_rpc::CoordinatorEdgeRpcClient;
use psy_core::job::job_id::QProvingJobDataID;
use rustyline::{Context, Editor, completion::{Completer, Pair}, error::ReadlineError, highlight::Highlighter, hint::Hinter};
use rustyline_derive::Helper;
use serde::Deserialize;
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter};



/// Command-line arguments for the REPL application.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(help = "The URL of the CoordinatorEdgeRpc server (e.g., http://127.0.0.1:1337)", default_value = "http://127.0.0.1:1337")]
    api_url: String,
}

// Placeholder for a missing type definition.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct CheckpointedMerkleHash<Hash> {
    pub hash: Hash,
    pub checkpoint_id: u64,
}

/// Defines all available REPL commands.
#[derive(Debug, EnumIter, AsRefStr)]
#[strum(serialize_all = "snake_case")]
enum Command {
    RegisterUser,
    GetPublicKeyForUserId,
    GetUserIdsForPublicKey,
    GetLatestCheckpointId,
    GetContractLeafData,
    GetContractCodeDefinition,
    GetCheckpointLeafData,
    GetCheckpointGlobalStateRoots,
    GetContractTreeStateHeights,
    GetLatestL2BlockState,
    GetL2BlockState,
    GetUserRegistrationTreeRoot,
    GetUserRegistrationTreeLeafHash,
    GetUserRegistrationTreeMerkleProof,
    GetUserTreeRoot,
    GetUserSubTreeMerkleProof,
    GetUserTopTreeMerkleProof,
    GetUserTopTreeCapRoot,
    GetUserLatestTopTreeCapRoot,
    GetUserLeafData,
    GetUserTreeMerkleProof,
    GetRealmRootAndLastModifiedCheckpoint,
    GetContractFunctionTreeRoot,
    GetContractFunctionTreeLeafHash,
    GetContractFunctionTreeMerkleProof,
    GetContractTreeRoot,
    GetContractTreeLeafHash,
    GetContractTreeMerkleProof,
    GetLatestCheckpointTreeRoot,
    GetCheckpointTreeRoot,
    GetCheckpointTreeLeafHash,
    GetCheckpointTreeMerkleProof,
    GenerateBatchProofMinerRewardProofs,
    GetRealmSyncInfo,
    GetCheckpointLeavesBatchRaw,
    Help,
    Exit,
}

/// Helper for rustyline providing hints and completions.
#[derive(Helper)]
struct ReplHelper {
    commands: BTreeMap<&'static str, &'static str>,
}

impl ReplHelper {
    fn new() -> Self {
        let mut commands = BTreeMap::new();
        commands.insert("register_user", r#"'{"fingerprint":"0x...","public_key_param":"0x..."}'"#);
        commands.insert("get_public_key_for_user_id", "<user_id>");
        commands.insert("get_user_ids_for_public_key", "<public_key_hex> <start_user_id> <count>");
        commands.insert("get_latest_checkpoint_id", "");
        commands.insert("get_canonical_chain_ref", "");
        commands.insert("get_contract_leaf_data", "<contract_id>");
        commands.insert("get_contract_code_definition", "<contract_id>");
        commands.insert("get_checkpoint_leaf_data", "<checkpoint_id>");
        commands.insert("get_checkpoint_global_state_roots", "<checkpoint_id>");
        commands.insert("get_contract_tree_state_heights", "<checkpoint_id> '[<contract_id1>,...]'");
        commands.insert("get_latest_l2_block_state", "");
        commands.insert("get_l2_block_state", "<checkpoint_id>");
        commands.insert("get_user_registration_tree_root", "<checkpoint_id>");
        commands.insert("get_user_registration_tree_leaf_hash", "<checkpoint_id> <leaf_index>");
        commands.insert("get_user_registration_tree_merkle_proof", "<checkpoint_id> <leaf_index>");
        commands.insert("get_user_tree_root", "<checkpoint_id>");
        commands.insert("get_user_sub_tree_merkle_proof", "<checkpoint_id> <root_level> <leaf_level> <leaf_index>");
        commands.insert("get_user_top_tree_merkle_proof", "<checkpoint_id> <leaf_level> <leaf_index>");
        commands.insert("get_user_top_tree_cap_root", "<checkpoint_id> <cap_level> <cap_index>");
        commands.insert("get_user_latest_top_tree_cap_root", "<cap_level> <cap_index>");
        commands.insert("get_user_leaf_data", "<checkpoint_id> <user_id>");
        commands.insert("get_user_tree_merkle_proof", "<checkpoint_id> <user_id>");
        commands.insert("get_realm_root_and_last_modified_checkpoint", "<checkpoint_id> <realm_id>");
        commands.insert("get_contract_function_tree_root", "<checkpoint_id> <contract_id>");
        commands.insert("get_contract_function_tree_leaf_hash", "<checkpoint_id> <contract_id> <function_id>");
        commands.insert("get_contract_function_tree_merkle_proof", "<checkpoint_id> <contract_id> <function_id>");
        commands.insert("get_contract_tree_root", "<checkpoint_id>");
        commands.insert("get_contract_tree_leaf_hash", "<checkpoint_id> <contract_id>");
        commands.insert("get_contract_tree_merkle_proof", "<checkpoint_id> <contract_id>");
        commands.insert("get_latest_checkpoint_tree_root", "");
        commands.insert("get_checkpoint_tree_root", "<checkpoint_id>");
        commands.insert("get_checkpoint_tree_leaf_hash", "<checkpoint_id> <leaf_checkpoint_id>");
        commands.insert("get_checkpoint_tree_merkle_proof", "<checkpoint_id> <leaf_checkpoint_id>");
        commands.insert("generate_batch_proof_miner_reward_proofs", r#"'[{"job_data_id":{...},"reward_path_info":...},...]"'"#);
        commands.insert("get_realm_sync_info", "<checkpoint_id>");
        commands.insert("get_checkpoint_leaves_batch_raw", "<start_checkpoint_id> <count>");
        commands.insert("help", "");
        commands.insert("exit", "");
        Self { commands }
    }
}

impl Completer for ReplHelper {
    type Candidate = Pair;
    fn complete(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let (start, word) = rustyline::completion::extract_word(line, pos, None, &[
            b' ', b'\t', b'\n', b'"', b'\\', b'\'', b'`', b'@', b'$', b'>', b'<', b'=', b';', b'|', b'&',
            b'{', b'(', b'\0',
        ]);
        let completions = Command::iter()
            .filter(|c| c.as_ref().starts_with(word))
            .map(|c| Pair { display: c.as_ref().to_string(), replacement: c.as_ref().to_string() })
            .collect();
        Ok((start, completions))
    }
}

impl Hinter for ReplHelper {
    fn hint(&self, line: &str, pos: usize, _ctx: &Context<'_>) -> Option<String> {
        if line.is_empty() || pos < line.len() { return None; }
        let first_word = line.split_whitespace().next().unwrap_or("");
        self.commands.get(first_word).and_then(|hint| {
            if hint.is_empty() { None } else { Some(format!(" {}", hint)) }
        })
    }
}
impl Highlighter for ReplHelper {}

/// Parses a single whitespace-separated argument.
fn parse_arg<T: FromStr>(args: &mut std::str::SplitWhitespace, name: &str) -> anyhow::Result<T>
where
    <T as FromStr>::Err: std::fmt::Display,
{
    let arg_str = args.next().ok_or_else(|| anyhow::anyhow!("Missing argument: <{}>", name))?;
    arg_str.parse::<T>().map_err(|e| anyhow::anyhow!("Failed to parse argument '{}': {}", name, e))
}

/// Parses a single argument from the remaining part of the string, expected to be JSON.
fn parse_json_arg<T: for<'de> Deserialize<'de>>(args: &mut std::str::SplitWhitespace, name: &str) -> anyhow::Result<T> {
    let json_str = args.collect::<Vec<&str>>().join(" ");
    if json_str.is_empty() {
        return Err(anyhow::anyhow!("Missing JSON argument: <{}>", name));
    }
    serde_json::from_str(&json_str).map_err(|e| anyhow::anyhow!("Failed to parse JSON for '{}': {}", name, e))
}

/// Parses a hex string argument for hash types.
fn parse_hex_arg<H: QHashBase>(args: &mut std::str::SplitWhitespace, name: &str) -> anyhow::Result<H> {
    let hex_str = args.next().ok_or_else(|| anyhow::anyhow!("Missing hex string argument: <{}>", name))?;
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    H::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("Failed to parse hash from hex for '{}': {}", name, e))
}

pub struct ReplHashTypes;
impl QNetworkHashTypes for ReplHashTypes {
    type F = parth_core::PF;
    type HasherBase = PoseidonHasher;
    type QHash = parth_core::PHash;
}

/// Main application entry point.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("Connecting to {}...", args.api_url);
    let client: HttpClient = HttpClientBuilder::default().build(&args.api_url)?;
    println!("Connected. Type 'help' for a list of commands, or 'exit' to quit.");

    let helper = ReplHelper::new();
    let mut rl = Editor::<ReplHelper>::new();
    rl.set_helper(Some(helper));
    rl.load_history(".coordinator_edge_repl_history").ok();

    loop {
        match rl.readline(">> ") {
            Ok(line) => {
                let line_trimmed = line.trim();
                if line_trimmed.is_empty() { continue; }
                rl.add_history_entry(line_trimmed);

                if matches!(line_trimmed, "exit" | "quit") { break; }
                if line_trimmed == "help" {
                    println!("Available commands:");
                    for (cmd, hint) in &rl.helper().unwrap().commands {
                        println!("  {:45} {}", cmd, hint);
                    }
                    continue;
                }

                match execute_command::<ReplHashTypes, _>(&client, line_trimmed).await {
                    Ok(response) => println!("{}", response),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
            Err(err) => {
                eprintln!("REPL Error: {:?}", err);
                break;
            }
        }
    }
    rl.save_history(".coordinator_edge_repl_history")?;
    Ok(())
}

/// Parses the command and executes the corresponding RPC call.
async fn execute_command<
    N: QNetworkHashTypes + 'static,
    C: CoordinatorEdgeRpcClient<N::F, N::QHash, QProvingJobDataID, Vec<u8>> + 'static,
>(client: &C, line: &str) -> anyhow::Result<String> {
    let mut args = line.split_whitespace();
    let cmd_str = args.next().unwrap_or("");

    let result = match cmd_str {
        "register_user" => {
            let res = client.register_user(parse_json_arg(&mut args, "public_key")?).await?;
            format!("{:#?}", res)
        }
        "get_public_key_for_user_id" => {
            let res = client.get_public_key_for_user_id(parse_arg(&mut args, "user_id")?).await?;
            format!("{:#?}", res)
        }
        "get_user_ids_for_public_key" => {
            let key = parse_hex_arg(&mut args, "public_key")?;
            let start = parse_arg(&mut args, "start_user_id")?;
            let count = parse_arg(&mut args, "count")?;
            let res = client.get_user_ids_for_public_key(key, start, count).await?;
            format!("{:#?}", res)
        }
        "get_latest_checkpoint_id" => format!("{:#?}", client.get_latest_checkpoint_id().await?),
        "get_canonical_chain_ref" => format!("{:#?}", client.get_canonical_chain_ref().await?),
        "get_contract_leaf_data" => format!("{:#?}", client.get_contract_leaf_data(parse_arg(&mut args, "contract_id")?).await?),
        "get_contract_code_definition" => format!("{:#?}", client.get_contract_code_definition(parse_arg(&mut args, "contract_id")?).await?),
        "get_checkpoint_leaf_data" => format!("{:#?}", client.get_checkpoint_leaf_data(parse_arg(&mut args, "checkpoint_id")?).await?),
        "get_checkpoint_global_state_roots" => format!("{:#?}", client.get_checkpoint_global_state_roots(parse_arg(&mut args, "checkpoint_id")?).await?),
        "get_contract_tree_state_heights" => {
            let id = parse_arg(&mut args, "checkpoint_id")?;
            let c_ids = parse_json_arg(&mut args, "contract_ids")?;
            format!("{:#?}", client.get_contract_tree_state_heights(id, c_ids).await?)
        }
        "get_latest_l2_block_state" => format!("{:#?}", client.get_latest_l2_block_state().await?),
        "get_l2_block_state" => format!("{:#?}", client.get_l2_block_state(parse_arg(&mut args, "checkpoint_id")?).await?),
        "get_user_registration_tree_root" => format!("{:#?}", client.get_user_registration_tree_root(parse_arg(&mut args, "checkpoint_id")?).await?),
        "get_user_registration_tree_leaf_hash" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "leaf_index")?;
            format!("{:#?}", client.get_user_registration_tree_leaf_hash(id1, id2).await?)
        }
        "get_user_registration_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "leaf_index")?;
            format!("{:#?}", client.get_user_registration_tree_merkle_proof(id1, id2).await?)
        }
        "get_user_tree_root" => format!("{:#?}", client.get_user_tree_root(parse_arg(&mut args, "checkpoint_id")?).await?),
        "get_user_sub_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "root_level")?;
            let id3 = parse_arg(&mut args, "leaf_level")?;
            let id4 = parse_arg(&mut args, "leaf_index")?;
            format!("{:#?}", client.get_user_sub_tree_merkle_proof(id1, id2, id3, id4).await?)
        }
        "get_user_top_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "leaf_level")?;
            let id3 = parse_arg(&mut args, "leaf_index")?;
            format!("{:#?}", client.get_user_top_tree_merkle_proof(id1, id2, id3).await?)
        }
        "get_user_top_tree_cap_root" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "cap_level")?;
            let id3 = parse_arg(&mut args, "cap_index")?;
            format!("{:#?}", client.get_user_top_tree_cap_root(id1, id2, id3).await?)
        }
        "get_user_latest_top_tree_cap_root" => {
            let id1 = parse_arg(&mut args, "cap_level")?;
            let id2 = parse_arg(&mut args, "cap_index")?;
            format!("{:#?}", client.get_user_latest_top_tree_cap_root(id1, id2).await?)
        }
        "get_user_leaf_data" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            format!("{:#?}", client.get_user_leaf_data(id1, id2).await?)
        }
        "get_user_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            format!("{:#?}", client.get_user_tree_merkle_proof(id1, id2).await?)
        }
        "get_realm_root_and_last_modified_checkpoint" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "realm_id")?;
            let res = client.get_realm_root_and_last_modified_checkpoint(id1, id2).await?;
            format!("{:#?}", res)
        }
        "get_contract_function_tree_root" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "contract_id")?;
            format!("{:#?}", client.get_contract_function_tree_root(id1, id2).await?)
        }
        "get_contract_function_tree_leaf_hash" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "contract_id")?;
            let id3 = parse_arg(&mut args, "function_id")?;
            format!("{:#?}", client.get_contract_function_tree_leaf_hash(id1, id2, id3).await?)
        }
        "get_contract_function_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "contract_id")?;
            let id3 = parse_arg(&mut args, "function_id")?;
            format!("{:#?}", client.get_contract_function_tree_merkle_proof(id1, id2, id3).await?)
        }
        "get_contract_tree_root" => format!("{:#?}", client.get_contract_tree_root(parse_arg(&mut args, "checkpoint_id")?).await?),
        "get_contract_tree_leaf_hash" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "contract_id")?;
            format!("{:#?}", client.get_contract_tree_leaf_hash(id1, id2).await?)
        }
        "get_contract_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "contract_id")?;
            format!("{:#?}", client.get_contract_tree_merkle_proof(id1, id2).await?)
        }
        "get_latest_checkpoint_tree_root" => format!("{:#?}", client.get_latest_checkpoint_tree_root().await?),
        "get_checkpoint_tree_root" => format!("{:#?}", client.get_checkpoint_tree_root(parse_arg(&mut args, "checkpoint_id")?).await?),
        "get_checkpoint_tree_leaf_hash" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "leaf_checkpoint_id")?;
            format!("{:#?}", client.get_checkpoint_tree_leaf_hash(id1, id2).await?)
        }
        "get_checkpoint_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "leaf_checkpoint_id")?;
            format!("{:#?}", client.get_checkpoint_tree_merkle_proof(id1, id2).await?)
        }
        "generate_batch_proof_miner_reward_proofs" => {
            let id1 = parse_arg(&mut args, "unique_pending_id")?;
            let ids = parse_json_arg(&mut args, "job_ids")?;
            format!("{:#?}", client.generate_batch_proof_miner_reward_proofs(id1, ids).await?)
        }
        "get_realm_sync_info" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "realm_id")?;
            format!("{:#?}", client.get_realm_sync_info(id1, id2).await?)
        }
        "get_checkpoint_leaves_batch_raw" => {
            let id1 = parse_arg(&mut args, "start_checkpoint_id")?;
            let id2 = parse_arg(&mut args, "count")?;
            let res = client.get_checkpoint_leaves_batch_raw(id1, id2).await?;
            format!("Received {} bytes: {}", res.len(), hex::encode(res))
        }
        _ => format!("Unknown command: '{}'. Type 'help' for a list of commands.", cmd_str),
    };
    Ok(result)
}
