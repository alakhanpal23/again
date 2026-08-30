class Widget:
    def __init__(self, name: str):
        self.name = name


def build_widget(name: str) -> Widget:
    return Widget(name)
