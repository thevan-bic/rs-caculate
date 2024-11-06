use std::sync::atomic::{AtomicUsize, Ordering};
use ethers::abi::Abi;
use ethers::prelude::*;
use ethers::utils::{keccak256, get_create2_address};
use dotenv::dotenv;
use serde::Deserialize;
use std::{env, fs::File, io::BufReader, sync::Arc};
use std::error::Error;
use hex::FromHex;
use rayon::prelude::*;
// use rand::rngs::StdRng;
// use rand::{Rng, SeedableRng};

// Struct to represent the contract JSON file format
#[derive(Deserialize)]
struct ContractJson {
    abi: serde_json::Value,
    bytecode: String,
}

// // Atomic counter to ensure unique salts across threads
// static SALT_COUNTER: AtomicUsize = AtomicUsize::new(0);
// 
// fn generate_unique_salt() -> [u8; 32] {
//     // Get a unique counter value
//     let counter = SALT_COUNTER.fetch_add(1, Ordering::SeqCst);
// 
//     // Initialize a seeded RNG with the counter value for determinism and uniqueness
//     let mut rng = StdRng::seed_from_u64(counter as u64);
// 
//     // Generate 32 bytes for the salt
//     let mut salt = [0u8; 32];
//     rng.fill(&mut salt);
//     salt
// }

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load environment variables
    dotenv().ok();

    // Get the entry point and default operator from environment variables
    let entry_point: Address = env::var("ENTRY_POINT")?.parse()?;
    let default_operator: Address = env::var("BIC_DEFAULT_OPERATOR")?.parse()?;

    // Initialize the provider and signer
    let provider = Provider::<Http>::try_from("https://sepolia-rollup.arbitrum.io/rpc")?;
    // Load the contract JSON file
    let file = File::open("./out/Bambo139.json")?;

    let reader = BufReader::new(file);
    let contract_json: ContractJson = serde_json::from_reader(reader)?;

    // Parse the contract ABI and convert bytecode to Bytes
    let abi: Abi = serde_json::from_value(contract_json.abi)?;
    let bytecode = Bytes::from(Vec::from_hex(contract_json.bytecode.trim_start_matches("0x"))?);



    // Prepare the contract factory with ABI and bytecode from JSON
    let contract_factory = ContractFactory::new(abi, bytecode, Arc::new(provider));

    // Prepare the constructor arguments
    let args = (entry_point, default_operator);

    // Get the bytecode combined with constructor arguments (bytecodeWithArgs)
    let deployer = contract_factory.deploy(args)?.legacy();
    let bytecode_with_args = deployer.tx.data().unwrap().to_vec();
    println!("{:?}", hex::encode(&bytecode_with_args));
    // Set up the external contract ABI
    let create_call_abi = [
        "function performCreate(uint256 value, bytes memory deploymentData) public returns (address newContract)",
        "function performCreate2(uint256 value, bytes memory deploymentData, bytes32 salt) public returns (address newContract)"
    ];

    // Connect to the external contract using the ABI and address
    let create_call_address: Address = "0x762fcf49c5ef21510755191bbed6aa2a702f0348".parse()?;
    // let create_call_contract = Contract::new(create_call_address, Abi::parse_str(&create_call_abi.join("\n"))?, Arc::new(deployer));

    (0..usize::MAX).into_par_iter().find_map_any(|_| {
        // Generate a random salt
        let salt: [u8; 32] = rand::random();
        
        // try to not duplicate salt but result not improve calculation speed
        // let salt: [u8; 32] = generate_unique_salt();

        let computed_address = compute_create2_address(create_call_address, &salt, &bytecode_with_args);

        // Check if computed address matches the desired condition
        if computed_address.to_string().to_lowercase().starts_with("0xb139")
            && computed_address.to_string().to_lowercase().ends_with("b139") {
            println!("-");
            println!("-");
            println!("-");
            println!("Perfect result!");
            println!("Salt: 0x{}", hex::encode(salt));
            println!("Computed Address: {}", computed_address);
            Some(())
        } else if computed_address.to_string().to_lowercase().starts_with("0xb139")
            && (computed_address.to_string().to_lowercase().ends_with("139")
            || computed_address.to_string().to_lowercase().ends_with("668")
            || computed_address.to_string().to_lowercase().ends_with("688")
            || computed_address.to_string().to_lowercase().ends_with("888")) {
            println!("-");
            println!("-");
            println!("Excellent result!");
            println!("Salt: 0x{}", hex::encode(salt));
            println!("Computed Address: {}", computed_address);
            None
        } else if computed_address.to_string().to_lowercase().starts_with("0xb139")
            && (computed_address.to_string().to_lowercase().ends_with("39")
            || computed_address.to_string().to_lowercase().ends_with("79")
            || computed_address.to_string().to_lowercase().ends_with("68")
            || computed_address.to_string().to_lowercase().ends_with("88")) {
            println!("-");
            println!("Great result!");
            println!("Salt: 0x{}", hex::encode(salt));
            println!("Computed Address: {}", computed_address);
            None
        } else if computed_address.to_string().to_lowercase().starts_with("0xb139") {
            println!("Fine result!");
            println!("Salt: 0x{}", hex::encode(salt));
            println!("Computed Address: {}", computed_address);
            None
        } else {
            None
        }
    });

    Ok(())
}


// Helper function to compute CREATE2 address
fn compute_create2_address(sender_address: Address, salt: &[u8; 32], deployment_data: &[u8]) -> Address {
    let bytecode_hash = keccak256(deployment_data);

    // Concatenate as per CREATE2 specification
    let mut data = Vec::with_capacity(1 + 20 + 32 + 32);
    data.push(0xff); // Fixed prefix for CREATE2
    data.extend_from_slice(sender_address.as_bytes());
    data.extend_from_slice(salt);
    data.extend_from_slice(&bytecode_hash);

    // Hash the final concatenated data
    let result_hash = keccak256(&data);

    // Return the last 20 bytes as the address
    Address::from_slice(&result_hash[12..])
    // get_create2_address(sender_address, salt, &bytecode_hash)
}
