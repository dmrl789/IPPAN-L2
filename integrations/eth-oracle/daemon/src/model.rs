#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectScore {
    pub subject_id: [u8; 32],
    pub score: u64,
}
