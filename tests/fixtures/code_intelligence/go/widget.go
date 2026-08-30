package widget

type Widget struct {
	Name string
}

func BuildWidget(name string) Widget {
	return Widget{Name: name}
}
