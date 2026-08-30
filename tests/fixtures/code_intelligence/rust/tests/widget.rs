use fixture::parse_widget;

#[test]
fn parses_widget() {
    let widget = parse_widget("one");
    assert_eq!(widget.name, "one");
}
