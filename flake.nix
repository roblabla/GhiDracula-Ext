{
  description = "GhiDracula";

  nixConfig.bash-prompt = "\[\\u@ghidracula:\\w\]$ ";

  inputs = {
    nixpkgs.url      = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      rec {
        devShell = pkgs.mkShell (rec {
          nativeBuildInputs = with pkgs; [
            git

            gradle
            jdk16
          ];
        });
      }
    );
}
