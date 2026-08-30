from widget import build_widget


def test_build_widget():
    assert build_widget("one").name == "one"
