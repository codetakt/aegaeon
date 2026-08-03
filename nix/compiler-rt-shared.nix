{
  pkgs,
  llvmPackages ? pkgs.llvmPackages_20,
}:
let
  baseCompilerRt = llvmPackages.compiler-rt;
in
baseCompilerRt.overrideAttrs (old: {
  pname = "${old.pname}-shared";
  cmakeFlags = (old.cmakeFlags or [ ]) ++ [
    "-DCOMPILER_RT_BUILD_SANITIZERS=ON"
    "-DCOMPILER_RT_BUILD_SHARED=ON"
    "-DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON"
    "-DSANITIZER_ENABLE_SHARED=ON"
  ];
  meta =
    let
      baseMeta = old.meta or { };
      baseDesc = baseMeta.description or "";
    in
    baseMeta
    // {
      description = "${baseDesc} (shared ASan runtimes enabled)";
    };
})
