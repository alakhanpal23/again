package widget

import "testing"

func TestBuildWidget(t *testing.T) {
	if BuildWidget("one").Name != "one" {
		t.Fatal("unexpected widget")
	}
}
