use hub_fin::FinStore;

#[test]
fn state_version_can_be_set_and_read() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = FinStore::open(tmp.path()).expect("open");
    assert_eq!(store.get_state_version().unwrap(), None);
    store.set_state_version(2).unwrap();
    assert_eq!(store.get_state_version().unwrap(), Some(2));
}
