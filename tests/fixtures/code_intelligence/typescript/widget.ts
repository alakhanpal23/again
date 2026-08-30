export interface Widget {
  name: string;
}

export function renderWidget(widget: Widget): string {
  return widget.name;
}
