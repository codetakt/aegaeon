# Pure inventory construction; rejects ambiguous pins before any network access.
registers:
let
  add =
    inventory: source:
    let
      filename = builtins.baseNameOf source.uri;
      canonical =
        builtins.match "https://(www[.]rfc-editor[.]org|www[.]ietf[.]org|openid[.]net)/[A-Za-z0-9_./-]+" source.uri
        != null;
      entry = source // {
        inherit filename;
      };
      conflict = index: key: builtins.hasAttr key index && index.${key} != entry;
    in
    if !canonical || builtins.match "[A-Za-z0-9_-]+[.](txt|html)" filename == null then
      throw "Assurance source must have a canonical HTTPS URI and a safe text/HTML basename: ${source.uri}"
    else if builtins.match "[0-9a-f]{64}" source.sha256 == null then
      throw "Assurance source requires a SHA-256 pin: ${source.id}"
    else if
      conflict inventory.byId source.id
      || conflict inventory.byUri source.uri
      || conflict inventory.byFilename filename
    then
      throw "Conflicting assurance source ID, URI or archive basename: ${source.id}"
    else
      {
        byId = inventory.byId // {
          ${source.id} = entry;
        };
        byUri = inventory.byUri // {
          ${source.uri} = entry;
        };
        byFilename = inventory.byFilename // {
          ${filename} = entry;
        };
      };
  inventory = builtins.foldl' add {
    byId = { };
    byUri = { };
    byFilename = { };
  } (builtins.concatLists (map (register: register.sources) registers));
in
builtins.attrValues inventory.byId
