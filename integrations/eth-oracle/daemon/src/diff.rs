use crate::model::SubjectMeta;
use crate::model::SubjectScore;
use std::collections::HashMap;

pub fn select_changed_scores(
    last_sent: &HashMap<[u8; 32], SubjectMeta>,
    latest: Vec<SubjectScore>,
) -> Vec<SubjectScore> {
    latest
        .into_iter()
        // v1: trigger updates on score changes; additionally, propagate label changes so the
        // on-chain mapping stays in sync for dApps.
        .filter(|s| match last_sent.get(&s.subject_id) {
            Some(prev) => prev.score != s.score || prev.label != s.label,
            None => true,
        })
        .collect()
}

pub fn diff_scores(
    last_sent: &HashMap<[u8; 32], SubjectMeta>,
    latest: Vec<SubjectScore>,
    max_updates_per_round: usize,
) -> Vec<SubjectScore> {
    let mut changed = select_changed_scores(last_sent, latest);
    if changed.len() > max_updates_per_round {
        changed.truncate(max_updates_per_round);
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_changed_or_new_subjects() {
        let s1 = SubjectScore {
            subject_id: [1u8; 32],
            score: 100,
            label: "@alice.ipn".to_string(),
            eth_address: None,
        };
        let s2 = SubjectScore {
            subject_id: [2u8; 32],
            score: 200,
            label: "@bob.ipn".to_string(),
            eth_address: Some("0x000000000000000000000000000000000000dEaD".to_string()),
        };

        let mut last = HashMap::new();
        last.insert(
            s1.subject_id,
            SubjectMeta {
                score: 100,
                label: "@alice.ipn".to_string(),
                eth_address: None,
            },
        );
        last.insert(
            s2.subject_id,
            SubjectMeta {
                score: 150,
                label: "@bob.ipn".to_string(),
                eth_address: None,
            },
        );

        let latest = vec![s1.clone(), s2.clone()];
        let changed = select_changed_scores(&last, latest);

        assert_eq!(changed, vec![s2]);
    }

    #[test]
    fn preserves_label_and_eth_address_in_diff_output() {
        let s = SubjectScore {
            subject_id: [9u8; 32],
            score: 777,
            label: "@carol.ipn".to_string(),
            eth_address: Some("0x1111111111111111111111111111111111111111".to_string()),
        };

        let mut last = HashMap::new();
        last.insert(
            s.subject_id,
            SubjectMeta {
                score: 1,
                label: "stale".to_string(),
                eth_address: None,
            },
        );

        let changed = diff_scores(&last, vec![s.clone()], 100);
        assert_eq!(changed, vec![s]);
    }

    #[test]
    fn selects_label_only_changes() {
        let s = SubjectScore {
            subject_id: [1u8; 32],
            score: 100,
            label: "new".to_string(),
            eth_address: None,
        };

        let mut last = HashMap::new();
        last.insert(
            s.subject_id,
            SubjectMeta {
                score: 100,
                label: "old".to_string(),
                eth_address: None,
            },
        );

        let changed = select_changed_scores(&last, vec![s.clone()]);
        assert_eq!(changed, vec![s]);
    }

    #[test]
    fn respects_max_updates_per_round() {
        let mut last = HashMap::new();
        // Last scores differ so all are "changed"
        for i in 0u8..10u8 {
            last.insert(
                [i; 32],
                SubjectMeta {
                    score: 0,
                    label: "stale".to_string(),
                    eth_address: None,
                },
            );
        }

        let latest = (0u8..10u8)
            .map(|i| SubjectScore {
                subject_id: [i; 32],
                score: (i as u64) + 1,
                label: format!("@user{i}.ipn"),
                eth_address: None,
            })
            .collect::<Vec<_>>();

        let changed = diff_scores(&last, latest, 3);
        assert_eq!(changed.len(), 3);
    }
}
