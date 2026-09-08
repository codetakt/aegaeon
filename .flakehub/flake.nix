{
  description = "Aegaeon server preview for internal development";

  inputs.aegaeon.url = "github:codetakt/aegaeon/main";

  outputs =
    { aegaeon, ... }:
    {
      packages.x86_64-linux.server = aegaeon.packages.x86_64-linux.server;
    };
}
