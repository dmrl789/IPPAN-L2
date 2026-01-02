use hub_fin::FinHub;
use l2_hub::HubStateMachine;
use l2_core::{L2Tx, L2HubId};

#[test]
fn test_fin_hub_determinism() {
    let mut hub1 = FinHub::new();
    let mut hub2 = FinHub::new();

    let tx = L2Tx {
        hub: L2HubId::Fin,
        tx_id: "tx-1".to_string(),
        payload: vec![1, 2, 3],
    };

    // Apply same tx to both
    let r1 = hub1.apply_tx(&tx);
    let r2 = hub2.apply_tx(&tx);

    // Receipts must match
    assert_eq!(r1, r2);

    // Execute same batch
    let txs = vec![tx.clone(), tx.clone()];
    let roots1 = hub1.execute_batch(&txs);
    let roots2 = hub2.execute_batch(&txs);

    assert_eq!(roots1, roots2);
}
