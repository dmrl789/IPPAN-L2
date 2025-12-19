use ippan_eth_oracle_daemon::diff::diff_scores;
use ippan_eth_oracle_daemon::model::SubjectScore;
use std::collections::HashMap;

#[test]
fn diff_scores_detects_changes_and_limits_to_max() {
    let unchanged = SubjectScore {
        subject_id: [1u8; 32],
        score: 100,
    };
    let changed_score = SubjectScore {
        subject_id: [2u8; 32],
        score: 200,
    };
    let new_subject = SubjectScore {
        subject_id: [3u8; 32],
        score: 300,
    };
    let extra = SubjectScore {
        subject_id: [4u8; 32],
        score: 400,
    };

    let mut last_sent = HashMap::new();
    last_sent.insert(unchanged.subject_id, 100);
    last_sent.insert(changed_score.subject_id, 150);

    let latest = vec![unchanged.clone(), changed_score.clone(), new_subject.clone(), extra.clone()];

    let out = diff_scores(&last_sent, latest, 2);

    // New + changed are detected; unchanged is ignored; limited to max=2.
    assert_eq!(out.len(), 2);
    assert!(out.contains(&changed_score));
    assert!(out.contains(&new_subject) || out.contains(&extra));
    assert!(!out.contains(&unchanged));
}

