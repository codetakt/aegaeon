# shellcheck shell=bash

ensure_jose_header_error_kind_wrapper() {
	local c_file="$GENERATED_EVERPARSE_DIR/JoseHeaderWrapper.c"
	local h_file="$GENERATED_EVERPARSE_DIR/JoseHeaderWrapper.h"

	if [[ -f $c_file ]] && ! grep -q "JoseHeaderGetJoseHeaderEntryErrorCode" "$c_file"; then
		C_FILE="$c_file" python3 <<-'PY'
			from pathlib import Path
			import os
			import re

			c_path = Path(os.environ["C_FILE"])
			text = c_path.read_text()
			pattern = re.compile(
			r"BOOLEAN JoseHeaderCheckJoseHeaderEntry\(uint8_t \*base, uint32_t len\) \{"
			r".*?\n\}",
			re.DOTALL,
			)
			replacement = "\n".join(
			[
			"static",
			"uint64_t JoseHeaderRunValidation(",
			"    uint8_t *base,",
			"    uint32_t len,",
			"    EVERPARSE_ERROR_FRAME *frame)",
			"{",
			"    frame->filled = FALSE;",
			"    return JoseHeaderValidateJoseHeaderEntry(",
			"        (uint8_t *)frame,",
			"        &DefaultErrorHandler,",
			"        base,",
			"        len,",
			"        0",
			"    );",
			"}",
			"",
			"BOOLEAN JoseHeaderCheckJoseHeaderEntry(uint8_t *base, uint32_t len) {",
			"    EVERPARSE_ERROR_FRAME frame;",
			"    uint64_t result = JoseHeaderRunValidation(base, len, &frame);",
			"    if (EverParseIsError(result))",
			"    {",
			"        if (frame.filled)",
			"        {",
			"            JoseHeaderEverParseError(frame.typename_s, frame.fieldname, frame.reason);",
			"        }",
			"        return FALSE;",
			"    }",
			"    return TRUE;",
			"}",
			"",
			"uint64_t JoseHeaderGetJoseHeaderEntryErrorCode(uint8_t *base, uint32_t len) {",
			"    EVERPARSE_ERROR_FRAME frame;",
			"    uint64_t result = JoseHeaderRunValidation(base, len, &frame);",
			"    if (EverParseIsError(result))",
			"    {",
			"        if (frame.filled)",
			"        {",
			"            JoseHeaderEverParseError(frame.typename_s, frame.fieldname, frame.reason);",
			"        }",
			"        return EverParseGetValidatorErrorKind(result);",
			"    }",
			"    return EVERPARSE_SUCCESS;",
			"}",
			]
			)
			text, count = pattern.subn(replacement, text, count=1)
			error = (
			"[everparse] unable to locate JoseHeaderCheckJoseHeaderEntry body "
			"in JoseHeaderWrapper.c"
			)
			if count != 1: raise SystemExit(error)
			c_path.write_text(text.expandtabs(4))
			print("[everparse] injected JoseHeaderGetJoseHeaderEntryErrorCode into JoseHeaderWrapper.c")
		PY
	elif [[ -f $c_file ]]; then
		C_FILE="$c_file" python3 <<-'PY'
			from pathlib import Path
			import os

			c_path = Path(os.environ["C_FILE"])
			text = c_path.read_text()
			normalized = text.expandtabs(4)
			if normalized != text: c_path.write_text(normalized); print(
			"[everparse] normalized JoseHeaderWrapper.c indentation"
			)
		PY
	fi

	if [[ -f $h_file ]] && ! grep -q "JoseHeaderGetJoseHeaderEntryErrorCode" "$h_file"; then
		H_FILE="$h_file" python3 <<-'PY'
			from pathlib import Path
			import os

			h_path = Path(os.environ["H_FILE"])
			text = h_path.read_text()
			needle = "BOOLEAN JoseHeaderCheckJoseHeaderEntry(uint8_t *base, uint32_t len);\n"
			snippet = (
			"BOOLEAN JoseHeaderCheckJoseHeaderEntry(uint8_t *base, uint32_t len);\n"
			"uint64_t JoseHeaderGetJoseHeaderEntryErrorCode(uint8_t *base, uint32_t len);\n"
			)
			error = (
			"[everparse] unable to locate JoseHeaderCheckJoseHeaderEntry declaration "
			"in JoseHeaderWrapper.h"
			)
			if needle not in text: raise SystemExit(error)
			h_path.write_text(text.replace(needle, snippet, 1).expandtabs(4))
			print("[everparse] injected JoseHeaderGetJoseHeaderEntryErrorCode into JoseHeaderWrapper.h")
		PY
	elif [[ -f $h_file ]]; then
		H_FILE="$h_file" python3 <<-'PY'
			from pathlib import Path
			import os

			h_path = Path(os.environ["H_FILE"])
			text = h_path.read_text()
			normalized = text.expandtabs(4)
			if normalized != text: h_path.write_text(normalized); print(
			"[everparse] normalized JoseHeaderWrapper.h indentation"
			)
		PY
	fi
}

ensure_id_token_jwt_validator() {
	local c_file="$GENERATED_EVERPARSE_DIR/IdTokenSchema.c"
	local h_file="$GENERATED_EVERPARSE_DIR/IdTokenSchema.h"

	if [[ -f $c_file ]] && ! grep -q "IdTokenSchemaValidateIdTokenJwtEntry" "$c_file"; then
		C_FILE="$c_file" python3 <<-'PY'
			from pathlib import Path
			import os
			c_path = Path(os.environ["C_FILE"])
			text = c_path.read_text()
			needle = "uint64_t\nIdTokenSchemaValidateIdTokenClaimsEntry"
			error = (
			"[everparse] unable to locate insertion point "
			"in IdTokenSchema.c"
			)
			if needle not in text: raise SystemExit(error)
			snippet = (
			"uint64_t\n"
			"IdTokenSchemaValidateIdTokenJwtEntry(\n"
			"  uint8_t *Ctxt,\n"
			"  void\n"
			"  (*Err)(\n"
			"    EverParseString x0,\n"
			"    EverParseString x1,\n"
			"    EverParseString x2,\n"
			"    uint8_t *x3,\n"
			"    uint8_t *x4,\n"
			"    uint64_t x5\n"
			"  ),\n"
			"  uint8_t *Input,\n"
			"  uint64_t InputLength,\n"
			"  uint64_t StartPosition\n"
			")\n"
			"{\n"
			"  uint64_t\n"
			"  positionAfterIdTokenJwtEntry =\n"
			"    ValidateLenPrefixedBytes(Ctxt,\n"
			"      Err,\n"
			"      Input,\n"
			"      InputLength,\n"
			"      StartPosition);\n"
			"  uint64_t positionAfterheader;\n"
			"  if (EverParseIsSuccess(positionAfterIdTokenJwtEntry))\n"
			"  {\n"
			"    positionAfterheader = positionAfterIdTokenJwtEntry;\n"
			"  }\n"
			"  else\n"
			"  {\n"
			"    Err(\"_id_token_jwt_entry\",\n"
			"      \"header\",\n"
			"      EverParseErrorReasonOfResult(positionAfterIdTokenJwtEntry),\n"
			"      Ctxt,\n"
			"      Input,\n"
			"      StartPosition);\n"
			"    positionAfterheader = positionAfterIdTokenJwtEntry;\n"
			"  }\n"
			"  if (EverParseIsError(positionAfterheader))\n"
			"  {\n"
			"    return positionAfterheader;\n"
			"  }\n"
			"  uint64_t\n"
			"  positionAfterIdTokenJwtEntry0 =\n"
			"    ValidateLenPrefixedBytes(Ctxt,\n"
			"      Err,\n"
			"      Input,\n"
			"      InputLength,\n"
			"      positionAfterheader);\n"
			"  uint64_t positionAfterpayload;\n"
			"  if (EverParseIsSuccess(positionAfterIdTokenJwtEntry0))\n"
			"  {\n"
			"    positionAfterpayload = positionAfterIdTokenJwtEntry0;\n"
			"  }\n"
			"  else\n"
			"  {\n"
			"    Err(\"_id_token_jwt_entry\",\n"
			"      \"payload\",\n"
			"      EverParseErrorReasonOfResult(positionAfterIdTokenJwtEntry0),\n"
			"      Ctxt,\n"
			"      Input,\n"
			"      positionAfterheader);\n"
			"    positionAfterpayload = positionAfterIdTokenJwtEntry0;\n"
			"  }\n"
			"  if (EverParseIsError(positionAfterpayload))\n"
			"  {\n"
			"    return positionAfterpayload;\n"
			"  }\n"
			"  uint64_t\n"
			"  positionAfterIdTokenJwtEntry1 =\n"
			"    ValidateLenPrefixedBytes(Ctxt,\n"
			"      Err,\n"
			"      Input,\n"
			"      InputLength,\n"
			"      positionAfterpayload);\n"
			"  uint64_t positionAftersignature;\n"
			"  if (EverParseIsSuccess(positionAfterIdTokenJwtEntry1))\n"
			"  {\n"
			"    positionAftersignature = positionAfterIdTokenJwtEntry1;\n"
			"  }\n"
			"  else\n"
			"  {\n"
			"    Err(\"_id_token_jwt_entry\",\n"
			"      \"signature\",\n"
			"      EverParseErrorReasonOfResult(positionAfterIdTokenJwtEntry1),\n"
			"      Ctxt,\n"
			"      Input,\n"
			"      positionAfterpayload);\n"
			"    positionAftersignature = positionAfterIdTokenJwtEntry1;\n"
			"  }\n"
			"  return positionAftersignature;\n"
			"}\n"
			)
			text = text.replace(needle, snippet + "\n" + needle, 1)
			c_path.write_text(text)
			print(
			"[everparse] injected IdTokenSchemaValidateIdTokenJwtEntry "
			"into IdTokenSchema.c"
			)
		PY
	fi

	if [[ -f $h_file ]] && ! grep -q "IdTokenSchemaValidateIdTokenJwtEntry" "$h_file"; then
		H_FILE="$h_file" python3 <<-'PY'
			from pathlib import Path
			import os
			h_path = Path(os.environ["H_FILE"])
			text = h_path.read_text()
			needle = "uint64_t\nIdTokenSchemaValidateIdTokenClaimsEntry"
			error = (
			"[everparse] unable to locate insertion point "
			"in IdTokenSchema.h"
			)
			if needle not in text: raise SystemExit(error)
			snippet = (
			"uint64_t\n"
			"IdTokenSchemaValidateIdTokenJwtEntry(\n"
			"  uint8_t *Ctxt,\n"
			"  void\n"
			"  (*Err)(\n"
			"    EverParseString x0,\n"
			"    EverParseString x1,\n"
			"    EverParseString x2,\n"
			"    uint8_t *x3,\n"
			"    uint8_t *x4,\n"
			"    uint64_t x5\n"
			"  ),\n"
			"  uint8_t *Input,\n"
			"  uint64_t InputLength,\n"
			"  uint64_t StartPosition\n"
			");\n"
			)
			text = text.replace(needle, snippet + needle, 1)
			h_path.write_text(text)
			print(
			"[everparse] injected IdTokenSchemaValidateIdTokenJwtEntry "
			"into IdTokenSchema.h"
			)
		PY
	fi
}

canonicalize_everparse_dir() {
	local generated_dir="$1"
	local root
	root="$(git rev-parse --show-toplevel)"

	python3 - "$root" "$generated_dir" <<-'PY'
		import os
		from pathlib import Path
		import re
		import subprocess
		import sys

		root = Path(sys.argv[1]).resolve()
		generated_dir = Path(sys.argv[2]).resolve()
		try:
		    relative_dir = generated_dir.relative_to(root)
		except ValueError as error:
		    raise SystemExit(f"generated directory is outside repository: {generated_dir}") from error

		tracked = subprocess.check_output(
		    ["git", "-C", str(root), "ls-files", "-z", "--", os.fspath(relative_dir)]
		).split(b"\0")
		for encoded_path in filter(None, tracked):
		    path = root / os.fsdecode(encoded_path)
		    raw = path.read_bytes()
		    canonical = re.sub(rb"[ \t]+(?=\r?\n)", b"", raw)
		    crlf_count = canonical.count(b"\r\n")
		    newline = b"\r\n" if crlf_count and crlf_count == canonical.count(b"\n") else b"\n"
		    canonical = re.sub(rb"(?:\r?\n)+\Z", b"", canonical) + newline
		    if canonical != raw:
		        path.write_bytes(canonical)
	PY
}

postprocess_everparse_dir() {
	local GENERATED_EVERPARSE_DIR="$1"
	ensure_jose_header_error_kind_wrapper
	ensure_id_token_jwt_validator
	canonicalize_everparse_dir "$GENERATED_EVERPARSE_DIR"
}
