pub mod model;

pub fn parse_widget(input: &str) -> model::Widget {
    model::Widget::new(input)
}
