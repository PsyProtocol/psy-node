use std::{collections::BTreeMap, str::FromStr};

use clap::{Parser, command};
use jsonrpsee::http_client::HttpClientBuilder;
use parth_core::{pgoldilocks::PoseidonHasher, protocol::core_types::QNetworkHashTypes};
use psy_api_core::realm::standard_edge_rpc::RealmEdgeRpcClient;
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
    #[arg(help = "The URL of the RealmEdgeRpc server (e.g., http://127.0.0.1:13380)", default_value = "http://127.0.0.1:13380")]
    api_url: String,
}

/// Defines all available REPL commands.
#[derive(Debug, EnumIter, AsRefStr)]
#[strum(serialize_all = "snake_case")]
enum Command {
    CheckUserIdInRealm,
    GetCheckpointLeafData,
    GetLatestCheckpointId,
    GetLatestL2BlockState,
    GetL2BlockState,
    GetLatestCheckpointTreeRoot,
    GetCheckpointTreeRoot,
    GetContractTreeStateHeights,
    GetCheckpointTreeLeafHash,
    GetCheckpointTreeMerkleProof,
    GetCheckpointGlobalStateRoots,
    GetUserLeafData,
    GetUserContractStateTreeRoot,
    GetUserContractStateTreeLeafHash,
    GetUserContractStateTreeNodes,
    GetUserContractTreeNodes,
    GetUserContractStateTreeMerkleProof,
    GetUserContractTreeRoot,
    GetUserContractTreeLeafHash,
    GetUserContractTreeMerkleProof,
    GetUserTreeRoot,
    GetUserTreeLeafHash,
    GetUserBottomTreeMerkleProof,
    GetUserSubTreeMerkleProof,
    GetUserTreeMerkleProof,
    GenerateBatchProofMinerRewardProofs,
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
        commands.insert("check_user_id_in_realm", "<user_id>");
        commands.insert("get_checkpoint_leaf_data", "<checkpoint_id>");
        commands.insert("get_latest_checkpoint_id", "");
        commands.insert("get_latest_l2_block_state", "");
        commands.insert("get_l2_block_state", "<checkpoint_id>");
        commands.insert("get_latest_checkpoint_tree_root", "");
        commands.insert("get_checkpoint_tree_root", "<checkpoint_id>");
        commands.insert("get_contract_tree_state_heights", "<checkpoint_id> '[<contract_id1>,...]'");
        commands.insert("get_checkpoint_tree_leaf_hash", "<checkpoint_id> <leaf_checkpoint_id>");
        commands.insert("get_checkpoint_tree_merkle_proof", "<checkpoint_id> <leaf_checkpoint_id>");
        commands.insert("get_checkpoint_global_state_roots", "<checkpoint_id>");
        commands.insert("get_user_leaf_data", "<checkpoint_id> <user_id>");
        commands.insert("get_user_contract_state_tree_root", "<checkpoint_id> <user_id> <contract_id>");
        commands.insert("get_user_contract_state_tree_leaf_hash", "<checkpoint_id> <user_id> <contract_id> <leaf_id>");
        commands.insert("get_user_contract_state_tree_nodes", r#"<checkpoint_id> '[{"user_id":1,"contract_id":2,"node_key":{"level":3,"index":4}},...]"'"#);
        commands.insert("get_user_contract_tree_nodes", r#"<checkpoint_id> '[{"user_id":1,"node_key":{"level":2,"index":3}},...]"'"#);
        commands.insert("get_user_contract_state_tree_merkle_proof", "<checkpoint_id> <user_id> <contract_id> <leaf_id>");
        commands.insert("get_user_contract_tree_root", "<checkpoint_id> <user_id>");
        commands.insert("get_user_contract_tree_leaf_hash", "<checkpoint_id> <user_id> <contract_id>");
        commands.insert("get_user_contract_tree_merkle_proof", "<checkpoint_id> <user_id> <contract_id>");
        commands.insert("get_user_tree_root", "<checkpoint_id>");
        commands.insert("get_user_tree_leaf_hash", "<checkpoint_id> <user_id>");
        commands.insert("get_user_bottom_tree_merkle_proof", "<root_level> <checkpoint_id> <user_id>");
        commands.insert("get_user_sub_tree_merkle_proof", "<checkpoint_id> <root_level> <leaf_level> <leaf_index>");
        commands.insert("get_user_tree_merkle_proof", "<checkpoint_id> <user_id>");
        commands.insert("generate_batch_proof_miner_reward_proofs", r#"<unique_pending_id> '[{"job_data_id":{...},"reward_path_info":...},...]"'"#);
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
        let mut completions = Vec::new();
        for cmd in Command::iter() {
            let cmd_str = cmd.as_ref();
            if cmd_str.starts_with(word) {
                completions.push(Pair {
                    display: cmd_str.to_string(),
                    replacement: cmd_str.to_string(),
                });
            }
        }
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


pub struct ReplHashTypes {

}

impl QNetworkHashTypes for ReplHashTypes {
    type F = parth_core::PF;
    type HasherBase = PoseidonHasher;

    type QHash =parth_core::PHash;
}

/// Main application entry point.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    println!("Connecting to {}...", args.api_url);
    let client = HttpClientBuilder::default().build(&args.api_url)?;
    println!("Connected. Type 'help' for a list of commands, or 'exit' to quit.");

    let helper = ReplHelper::new();
    let mut rl = Editor::<ReplHelper>::new();
    rl.set_helper(Some(helper));
    rl.load_history(".realm_edge_repl_history").ok();

    loop {
        match rl.readline(">> ") {
            Ok(line) => {
                let line_trimmed = line.trim();
                if line_trimmed.is_empty() { continue; }
                rl.add_history_entry(line_trimmed);

                match line_trimmed {
                    "exit" | "quit" => break,
                    "help" => {
                        println!("Available commands:");
                        for (cmd, hint) in &rl.helper().unwrap().commands {
                            println!("  {:45} {}", cmd, hint);
                        }
                        continue;
                    }
                    _ => {}
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
    rl.save_history(".realm_edge_repl_history")?;
    Ok(())
}

/// Parses the command and executes the corresponding RPC call.
async fn execute_command<
    N: QNetworkHashTypes + 'static,
    C: RealmEdgeRpcClient<N::F, N::QHash, QProvingJobDataID, Vec<u8>> + 'static,
>(client: &C, line: &str) -> anyhow::Result<String> {
    let mut args = line.split_whitespace();
    let cmd_str = args.next().unwrap_or("");

    let result = match cmd_str {
        "check_user_id_in_realm" => {
            let res = client.check_user_id_in_realm(parse_arg(&mut args, "user_id")?).await?;
            format!("{:#?}", res)
        }
        "get_checkpoint_leaf_data" => {
            let res = client.get_checkpoint_leaf_data(parse_arg(&mut args, "checkpoint_id")?).await?;
            format!("{:#?}", res)
        }
        "get_latest_checkpoint_id" => {
            let res = client.get_latest_checkpoint_id().await?;
            format!("{:#?}", res)
        }
        "get_latest_l2_block_state" => {
            let res = client.get_latest_l2_block_state().await?;
            format!("{:#?}", res)
        }
        "get_l2_block_state" => {
            let res = client.get_l2_block_state(parse_arg(&mut args, "checkpoint_id")?).await?;
            format!("{:#?}", res)
        }
        "get_latest_checkpoint_tree_root" => {
            let res = client.get_latest_checkpoint_tree_root().await?;
            format!("{:#?}", res)
        }
        "get_checkpoint_tree_root" => {
            let res = client.get_checkpoint_tree_root(parse_arg(&mut args, "checkpoint_id")?).await?;
            format!("{:#?}", res)
        }
        "get_contract_tree_state_heights" => {
            let id = parse_arg(&mut args, "checkpoint_id")?;
            let c_ids = parse_json_arg(&mut args, "contract_ids")?;
            let res = client.get_contract_tree_state_heights(id, c_ids).await?;
            format!("{:#?}", res)
        }
        "get_checkpoint_tree_leaf_hash" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "leaf_checkpoint_id")?;
            let res = client.get_checkpoint_tree_leaf_hash(id1, id2).await?;
            format!("{:#?}", res)
        }
        "get_checkpoint_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "leaf_checkpoint_id")?;
            let res = client.get_checkpoint_tree_merkle_proof(id1, id2).await?;
            format!("{:#?}", res)
        }
        "get_checkpoint_global_state_roots" => {
            let res = client.get_checkpoint_global_state_roots(parse_arg(&mut args, "checkpoint_id")?).await?;
            format!("{:#?}", res)
        }
        "get_user_leaf_data" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            let res = client.get_user_leaf_data(id1, id2).await?;
            format!("{:#?}", res)
        }
        "get_user_contract_state_tree_root" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            let id3 = parse_arg(&mut args, "contract_id")?;
            let res = client.get_user_contract_state_tree_root(id1, id2, id3).await?;
            format!("{:#?}", res)
        }
        "get_user_contract_state_tree_leaf_hash" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            let id3 = parse_arg(&mut args, "contract_id")?;
            let id4 = parse_arg(&mut args, "leaf_id")?;
            let res = client.get_user_contract_state_tree_leaf_hash(id1, id2, id3, id4).await?;
            format!("{:#?}", res)
        }
        "get_user_contract_state_tree_nodes" => {
            let id = parse_arg(&mut args, "checkpoint_id")?;
            let keys = parse_json_arg(&mut args, "keys")?;
            let res = client.get_user_contract_state_tree_nodes(id, keys).await?;
            format!("{:#?}", res)
        }
        "get_user_contract_tree_nodes" => {
            let id = parse_arg(&mut args, "checkpoint_id")?;
            let keys = parse_json_arg(&mut args, "keys")?;
            let res = client.get_user_contract_tree_nodes(id, keys).await?;
            format!("{:#?}", res)
        }
        "get_user_contract_state_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            let id3 = parse_arg(&mut args, "contract_id")?;
            let id4 = parse_arg(&mut args, "leaf_id")?;
            let res = client.get_user_contract_state_tree_merkle_proof(id1, id2, id3, id4).await?;
            format!("{:#?}", res)
        }
        "get_user_contract_tree_root" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            let res = client.get_user_contract_tree_root(id1, id2).await?;
            format!("{:#?}", res)
        }
        "get_user_contract_tree_leaf_hash" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            let id3 = parse_arg(&mut args, "contract_id")?;
            let res = client.get_user_contract_tree_leaf_hash(id1, id2, id3).await?;
            format!("{:#?}", res)
        }
        "get_user_contract_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            let id3 = parse_arg(&mut args, "contract_id")?;
            let res = client.get_user_contract_tree_merkle_proof(id1, id2, id3).await?;
            format!("{:#?}", res)
        }
        "get_user_tree_root" => {
            let res = client.get_user_tree_root(parse_arg(&mut args, "checkpoint_id")?).await?;
            format!("{:#?}", res)
        }
        "get_user_tree_leaf_hash" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            let res = client.get_user_tree_leaf_hash(id1, id2).await?;
            format!("{:#?}", res)
        }
        "get_user_bottom_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "root_level")?;
            let id2 = parse_arg(&mut args, "checkpoint_id")?;
            let id3 = parse_arg(&mut args, "user_id")?;
            let res = client.get_user_bottom_tree_merkle_proof(id1, id2, id3).await?;
            format!("{:#?}", res)
        }
        "get_user_sub_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "root_level")?;
            let id3 = parse_arg(&mut args, "leaf_level")?;
            let id4 = parse_arg(&mut args, "leaf_index")?;
            let res = client.get_user_sub_tree_merkle_proof(id1, id2, id3, id4).await?;
            format!("{:#?}", res)
        }
        "get_user_tree_merkle_proof" => {
            let id1 = parse_arg(&mut args, "checkpoint_id")?;
            let id2 = parse_arg(&mut args, "user_id")?;
            let res = client.get_user_tree_merkle_proof(id1, id2).await?;
            format!("{:#?}", res)
        }
        "generate_batch_proof_miner_reward_proofs" => {
            let id1 = parse_arg(&mut args, "unique_pending_id")?;
            let ids = parse_json_arg(&mut args, "job_ids")?;
            let res = client.generate_batch_proof_miner_reward_proofs(id1, ids).await?;
            format!("{:#?}", res)
        }
        _ => format!("Unknown command: '{}'. Type 'help' for a list of commands.", cmd_str),
    };

    Ok(result)
}
