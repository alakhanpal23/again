pub struct Widget {
    pub name: String,
}

impl Widget {
    pub fn new(name: &str) -> Self {
        Self { name: name.to_owned() }
    }
}
