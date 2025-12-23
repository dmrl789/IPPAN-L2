use assert_cmd::Command;
use base64::Engine as _;
use l2_core::l1_contract::{L1InclusionProof, L2BatchEnvelopeV1};
use std::path::PathBuf;

fn fin_node_cmd() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("fin-node"))
}

fn example_path(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.join("..").join("examples").join(name)
}

fn b64url32(bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64url(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .expect("base64url decode")
}

#[test]
fn mock_submit_creates_receipt_and_inclusion_is_deterministic() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let fin_example = example_path("batch_fin_v1.json");
    let raw = std::fs::read_to_string(&fin_example).expect("read example");
    let env: L2BatchEnvelopeV1 = serde_json::from_str(&raw).expect("parse example envelope");

    // 1) Submit (mock mode is default)
    fin_node_cmd()
        .current_dir(tmp.path())
        .args([
            "submit-batch",
            "--hub",
            "fin",
            "--file",
            fin_example.to_string_lossy().as_ref(),
        ])
        .assert()
        .success();

    // 2) Receipt exists
    let id = b64url32(env.idempotency_key.as_bytes());
    let receipt_path = tmp.path().join("receipts").join(format!("{id}.json"));
    assert!(receipt_path.exists(), "missing receipt: {receipt_path:?}");

    let receipt_raw = std::fs::read_to_string(&receipt_path).expect("read receipt");
    let receipt: serde_json::Value = serde_json::from_str(&receipt_raw).expect("parse receipt");
    assert_eq!(receipt["idempotency_key"], id);
    assert_eq!(receipt["contract_version"], "v1");

    let canonical_hash = b64url32(&env.canonical_hash_blake3().expect("canonical hash"));
    assert_eq!(receipt["canonical_hash"], canonical_hash);

    // 3) Inclusion proof matches mock algorithm:
    // proof = blake3(key || envelope_hash)
    let inclusion_out = fin_node_cmd()
        .current_dir(tmp.path())
        .args(["l1", "inclusion", "--id", &id])
        .output()
        .expect("run inclusion");
    assert!(inclusion_out.status.success());

    let proof_opt: Option<L1InclusionProof> =
        serde_json::from_slice(&inclusion_out.stdout).expect("decode inclusion json");
    let proof = proof_opt.expect("expected inclusion proof");

    let envelope_hash = env.canonical_hash_blake3().expect("envelope hash");
    let mut expected = blake3::Hasher::new();
    expected.update(env.idempotency_key.as_bytes());
    expected.update(&envelope_hash);
    let expected_bytes = expected.finalize().as_bytes().to_vec();

    let got_bytes = decode_b64url(
        serde_json::to_value(&proof.proof)
            .unwrap()
            .as_str()
            .unwrap(),
    );
    assert_eq!(got_bytes, expected_bytes);

    assert_eq!(proof.l1_tx_id.0, format!("mock:{id}"));
}

#[test]
fn mock_finality_returns_deterministic_proof() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fin_example = example_path("batch_fin_v1.json");
    let raw = std::fs::read_to_string(&fin_example).expect("read example");
    let env: L2BatchEnvelopeV1 = serde_json::from_str(&raw).expect("parse example envelope");
    let id = b64url32(env.idempotency_key.as_bytes());

    fin_node_cmd()
        .current_dir(tmp.path())
        .args([
            "submit-batch",
            "--hub",
            "fin",
            "--file",
            fin_example.to_string_lossy().as_ref(),
        ])
        .assert()
        .success();

    let tx = format!("mock:{id}");
    let out = fin_node_cmd()
        .current_dir(tmp.path())
        .args(["l1", "finality", "--tx", &tx])
        .output()
        .expect("run finality");
    assert!(out.status.success());

    let proof_opt: Option<L1InclusionProof> =
        serde_json::from_slice(&out.stdout).expect("decode finality json");
    let proof = proof_opt.expect("expected finality proof");
    assert!(proof.finalized);
    assert_eq!(proof.l1_tx_id.0, tx);
}
