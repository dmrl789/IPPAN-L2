use crate::model::SubjectScore;
use std::collections::HashMap;

pub fn select_changed_scores(
    last_sent: &HashMap<[u8; 32], u64>,
    latest: Vec<SubjectScore>,
) -> Vec<SubjectScore> {
    latest
        .into_iter()
        .filter(|s| last_sent.get(&s.subject_id).copied() != Some(s.score))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_changed_or_new_subjects() {
        let s1 = SubjectScore {
            subject_id: [1u8; 32],
            score: 100,
        };
        let s2 = SubjectScore {
            subject_id: [2u8; 32],
            score: 200,
        };

        let mut last = HashMap::new();
        last.insert(s1.subject_id, 100);
        last.insert(s2.subject_id, 150);

        let latest = vec![s1.clone(), s2.clone()];
        let changed = select_changed_scores(&last, latest);

        assert_eq!(changed, vec![s2]);
    }
}
