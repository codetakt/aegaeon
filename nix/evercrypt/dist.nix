{
  pkgs ? import <nixpkgs> { },
  src,
  version,
}:

pkgs.stdenv.mkDerivation rec {
  pname = "evercrypt-dist";
  inherit version src;

  # Dispatch complete SHA-224/256 blocks, including padding, through the
  # existing CPU policy. The new dispatch glue is outside upstream proofs.
  # Bind zero-context patch positions to the exact pinned source preimage.
  prePatch = ''
    echo "6cd390cc86d9054e3d577f75e1e4d1559a545ec22e4643179aa087c8bd612e4e  dist/gcc-compatible/Hacl_Hash_SHA2.c" | sha256sum -c -
  '';
  patches = [ ./sha256-cpu-policy.patch ];

  nativeBuildInputs = with pkgs; [
    bash
    coreutils
    findutils
    gnumake
    gnugrep
    gnused
    python3
  ];

  buildPhase = ''
    runHook preBuild
    (
      cd dist/gcc-compatible
      chmod +x ./configure
      bash ./configure
      make libevercrypt.a
    )
    runHook postBuild
  '';

  # The dispatch patch is active on Linux/x86-64, where GNU --wrap lets this
  # regression count actual SHA blocks and force unsupported CPU capabilities.
  doCheck =
    pkgs.stdenv.hostPlatform.isLinux
    && pkgs.stdenv.hostPlatform.isx86_64
    && pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform;
  checkPhase = ''
    runHook preCheck
    (
      cd dist/gcc-compatible
      mkdir dispatch-regression
      cp ${../../c/crypto_init.c} dispatch-regression/crypto_init.c
      cp ${../../c/crypto_init.h} dispatch-regression/crypto_init.h
      python3 ${../../tests/crypto/cpu_dispatch_vectors.py} > vectors.bin
      for mode in auto no-sha no-sse; do
        capability_flags=()
        case "$mode" in
          no-sha) capability_flags=(-DTEST_NO_SHA=1) ;;
          no-sse) capability_flags=(-DTEST_NO_SSE=1) ;;
        esac
        "$CC" ${../../tests/crypto/cpu_dispatch_test.c} dispatch-regression/crypto_init.c \
          -Idispatch-regression -I. -I../karamel/include -I../karamel/krmllib/dist/minimal \
          -O2 -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -pthread \
          "''${capability_flags[@]}" libevercrypt.a \
          -Wl,--wrap=EverCrypt_AutoConfig2_init -Wl,--wrap=sha256_update \
          -Wl,--wrap=check_sha -Wl,--wrap=check_sse -o "cpu-dispatch-$mode"
        "./cpu-dispatch-$mode" < vectors.bin
        "./cpu-dispatch-$mode" --threads < vectors.bin
      done
    )
    runHook postCheck
  '';

  installPhase = ''
        runHook preInstall

        mkdir -p $out/lib $out/include $out/lib/pkgconfig $out/share/licenses/evercrypt

        # Pinned primitives plus locally tested dispatch glue (see dudect.md).
        cp dist/gcc-compatible/libevercrypt.a $out/lib/

        # Public headers.
        cp dist/gcc-compatible/*.h $out/include/
        cp -r dist/gcc-compatible/internal $out/include/
        cp dist/gcc-compatible/config.h $out/include/

        # Upstream license (MIT) for the dist artifacts.
        cp dist/LICENSE.txt $out/share/licenses/evercrypt/LICENSE.txt

        cat > $out/lib/pkgconfig/evercrypt.pc <<EOF
    prefix=$out
    libdir=$out/lib
    includedir=$out/include

    Name: evercrypt
    Description: EverCrypt (HACL*) dist static library
    Version: ${version}
    Libs: -L$out/lib -levercrypt
    Cflags: -I$out/include
    EOF

        runHook postInstall
  '';

  meta = with pkgs.lib; {
    description = "EverCrypt dist build (static C library + headers + pkg-config)";
    homepage = "https://github.com/hacl-star/hacl-star";
    license = licenses.mit;
    platforms = platforms.all;
  };
}
