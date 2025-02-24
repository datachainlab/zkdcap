use dcap_quote_verifier::collateral::QvCollateral;
use dcap_quote_verifier::types::quotes::Quote;
use dcap_quote_verifier::quotes::verify_quote;
use risc0_zkvm::guest::env;

fn main() {
    let (quote, collateral, current_time): (Vec<u8>, Vec<u8>, u64) = env::read();

    let (quote, _) = Quote::from_bytes(&quote).unwrap();
    let collateral = QvCollateral::from_bytes(&collateral).unwrap();

    env::commit_slice(
        verify_quote(&quote, &collateral, current_time)
            .unwrap()
            .to_bytes()
            .as_slice(),
    );
}
