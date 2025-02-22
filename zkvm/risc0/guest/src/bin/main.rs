use dcap_quote_verifier::collaterals::IntelCollateral;
use dcap_quote_verifier::types::quotes::Quote;
use dcap_quote_verifier::quotes::verify_quote;
use risc0_zkvm::guest::env;

fn main() {
    let (quote, collaterals, current_time): (Vec<u8>, Vec<u8>, u64) = env::read();

    let quote = Quote::from_bytes(&quote).unwrap();
    let collaterals = IntelCollateral::from_bytes(&collaterals).unwrap();

    env::commit_slice(
        verify_quote(&quote, &collaterals, current_time)
            .unwrap()
            .to_bytes()
            .as_slice(),
    );
}
