{
  pkgs ? import <nixpkgs> { },
  src,
  version,
}:

pkgs.stdenv.mkDerivation rec {
  pname = "evercrypt-source";
  inherit version src;

  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    mkdir -p $out/share/evercrypt
    cp -R code $out/share/evercrypt/code
    cp -R providers/evercrypt $out/share/evercrypt/providers
    cp -R dist $out/share/evercrypt/dist
    cp -R specs $out/share/evercrypt/specs
    echo "EverCrypt sources installed to $out/share/evercrypt"
    runHook postInstall
  '';

  meta = with pkgs.lib; {
    description = "EverCrypt source drop (F* specs, C code, dist artifacts)";
    homepage = "https://github.com/hacl-star/hacl-star";
    license = licenses.asl20;
    platforms = platforms.all;
  };
}
