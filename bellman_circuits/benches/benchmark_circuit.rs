// Extern crate declarations
extern crate rand;
extern crate criterion;

// Use statements
use bellman_circuits::circuits::sha256;
use rand::thread_rng;
use bellman::{Circuit, groth16};
use criterion::{Criterion, BenchmarkGroup};
use criterion::measurement::Measurement;
use sha2::{Digest, Sha256};
use bellman::gadgets::multipack;
use bls12_381::{Bls12, Scalar};
use utilities::read_file_from_env_var;

// Benchmark for a given circuit
pub fn bench_circuit<M: Measurement, C: Circuit<Scalar> + Clone + 'static>(
    c: &mut BenchmarkGroup<'_, M>,
    circuit: C,
    public_inputs: Vec<Scalar>,
    params: groth16::Parameters<Bls12>
) {
    let rng = &mut thread_rng();
    let pvk = groth16::prepare_verifying_key(&params.vk);

    c.bench_function("setup_time", |b| {
        b.iter(|| { 
            let _ = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), rng).unwrap();
        })
    });

    c.bench_function("prover_time", |b| {
        b.iter(|| { 
            let _ = groth16::create_random_proof(circuit.clone(), &params, rng); 
        })
    });

    let proof = groth16::create_random_proof(circuit.clone(), &params, rng).unwrap(); 

    c.bench_function("verifier_time", |b| {
        b.iter(|| {
            let _ = groth16::verify_proof(&pvk, &proof, &public_inputs);        
        })
    });
}

// Benchmark for SHA-256
fn bench_sha256(c: &mut Criterion, input_str: String) {
    let mut group = c.benchmark_group("sha256");
    let (preimage_length, preimage) = sha256::get_sha256_data(input_str);

    // Pre-Compute public inputs
    let hash = Sha256::digest(&Sha256::digest(&preimage));
    let hash_bits = multipack::bytes_to_bits_le(&hash);
    let inputs = multipack::compute_multipacking(&hash_bits);

    // Define the circuit
    let circuit = sha256::Sha256Circuit {
        preimage: Some(preimage.clone()),
        preimage_length: preimage_length,
    };

    // Generate Parameters
    let params = groth16::generate_random_parameters::<Bls12, _, _>(circuit.clone(), &mut thread_rng()).unwrap();
    
    bench_circuit(&mut group, circuit, inputs, params);
}

fn main() {
    let mut criterion = Criterion::default()
        .configure_from_args()
        .sample_size(10);

    let input_file_str = read_file_from_env_var("INPUT_FILE".to_string());

    // Benchmark SHA-256 Circuit
    bench_sha256(&mut criterion, input_file_str);

    criterion.final_summary();
}
