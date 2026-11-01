## 2026-11-01 - Path Traversal in File Download and Screenshot
**Vulnerability:** User-controlled inputs (`arg.as` and `arg`) were concatenated directly with `runDir` without path traversal checks in the `download` and `screenshot` task steps in `standin/server/src/runner.mjs`.
**Learning:** File paths derived from user input or external configurations need to be validated to ensure they are contained within the intended base directory.
**Prevention:** Use `path.resolve` to get the absolute path and verify it starts with `path.resolve(baseDir) + path.sep` before writing any file.
