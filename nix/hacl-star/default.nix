{
  pkgs ? import <nixpkgs> { },
}:

{
  version = "2024.08.26";
  src = pkgs.fetchFromGitHub {
    owner = "hacl-star";
    repo = "hacl-star";
    rev = "531820c1af15cafc2437068fb565fa0b8b431e73";
    sha256 = "0sjsi6gqij65kcb4x6i384khwyfk1icmk55m68xi1a2ahj76bmbh";
  };
}
