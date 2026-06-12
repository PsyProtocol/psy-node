## Contribution Guide

1. Code should aim for simplicity, readability, and fewer errors, rather than optimizing for performance or line count.
2. Minimize the use of if-else statements, and avoid excessive nesting levels (not exceeding 3 levels).
3. Return early when encountering errors; for Options, prefer using ok_or to transform them into readable errors and return early.
4. Dependencies should be uniformly defined in the workspace and referenced in crates using workspace = true.
5. Avoid specifying fixed versions for dependencies; specify up to the minor version but not the patch level.
6. Prioritize code reusability by writing functions and traits instead of copy-pasting.
7. Each module should properly define its exported types, functions, etc., and external imports should use "use modName::*;" rather than importing each item individually with 100 lines of imports.
8. Don't over-comment; express intent through function and variable names, and add comments only where necessary - not every place needs a comment as that would reduce readability.
9. Tests should be in the same file as the code whenever possible, avoid creating too many tests directories.
