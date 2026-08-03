{
  pkgs ? import <nixpkgs> { },
  src,
  version,
}:

pkgs.stdenv.mkDerivation rec {
  pname = "evercrypt-dist";
  inherit version src;

  nativeBuildInputs = with pkgs; [
    bash
    coreutils
    findutils
    gnumake
    gnugrep
    gnused
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

  installPhase = ''
        runHook preInstall

        mkdir -p $out/lib $out/include $out/lib/pkgconfig $out/share/licenses/evercrypt

        # Static library (verified crypto primitives).
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
