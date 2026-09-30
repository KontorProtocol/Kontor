import { expect, test } from "vitest";
import { generate } from "@kontor/sdk";

function contract(
  context: string,
  parameters: string,
  fields = "items: list<u64>, next: option<string>",
) {
  return `package test:pagination;
world root {
  include kontor:built-in/built-in;
  use kontor:built-in/context.{proc-context, view-context, contract};
  use kontor:built-in/pagination.{cursor-request};
  record response { ${fields} }
  export init: async func(ctx: borrow<proc-context>) -> contract;
  export entries: async func(ctx: borrow<${context}>, ${parameters}) -> response;
}`;
}

test("only the imported request type enables pagination", () => {
  expect(
    generate(contract("view-context", "pagination: cursor-request")),
  ).toContain("PaginatedView<Response>");
  expect(
    generate(contract("view-context", "after: option<string>, limit: u64")),
  ).not.toContain("PaginatedView");
});

test.each([
  [
    "proc-context",
    "pagination: cursor-request",
    "items: list<u64>, next: option<string>",
  ],
  [
    "view-context",
    "a: cursor-request, b: cursor-request",
    "items: list<u64>, next: option<string>",
  ],
  [
    "view-context",
    "pagination: cursor-request, filter: string",
    "items: list<u64>, next: option<string>",
  ],
  [
    "view-context",
    "pagination: cursor-request",
    "items: u64, next: option<string>",
  ],
  [
    "view-context",
    "pagination: cursor-request",
    "items: list<u64>, next: option<u64>",
  ],
])(
  "invalid pagination declarations fail generation: %s %s %s",
  (context, parameters, fields) => {
    expect(() => generate(contract(context, parameters, fields))).toThrow(
      /paginated view/,
    );
  },
);

test("a local record with the same name and fields does not opt in", () => {
  const source = contract("view-context", "pagination: cursor-request").replace(
    "use kontor:built-in/pagination.{cursor-request};",
    "record cursor-request { after: option<string>, limit: option<u64> }",
  );
  expect(generate(source)).not.toContain("PaginatedView");
});
