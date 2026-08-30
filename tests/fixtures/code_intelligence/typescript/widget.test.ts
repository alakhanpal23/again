import { renderWidget } from "./widget";

test("renders a widget", () => {
  expect(renderWidget({ name: "one" })).toBe("one");
});
