<!--
SPDX-FileCopyrightText: 2026 SombrAbsol

SPDX-License-Identifier: MIT
-->

# aladump
<a href="https://github.com/SombrAbsol/aladump/actions/workflows/ci.yml"><img src="https://github.com/SombrAbsol/aladump/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://opensource.org/license/mit"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License: MIT (Expat)"></a>

Asset extractor for *Pokémon Trading Card Game Pocket*.

*Pokémon Trading Card Game Pocket* stores its encrypted assets using the Aladin asset system. aladump decrypts and converts these assets back into Unity assets. You can [download the latest build](#download) or [build the program from source](#building).

For more information about the Aladin asset system, see [the documentation](/docs/aladin.md).

## Download
|        | Linux | macOS | Windows |
| ------ | ----- | ----- | ------- |
| Latest | [Download](https://github.com/SombrAbsol/aladump/releases/download/latest/aladump-linux.zip) | [Download](https://github.com/SombrAbsol/aladump/releases/download/latest/aladump-macos.zip) | [Download](https://github.com/SombrAbsol/aladump/releases/download/latest/aladump-windows.zip) |

## Usage
### Getting the game assets
> [!IMPORTANT]
> These instructions assume you use the Android release of *Pokémon Trading Card Game Pocket*.

#### Requirements
* Download and install the following on your Android device:
  * *[Pokémon Trading Card Game Pocket](https://play.google.com/store/apps/details?id=jp.pokemon.pokemontcgp)*
  * [X-/APK/S Extractor & Installer](https://play.google.com/store/apps/details?id=domilopment.apkextractor)
  
* Download and install the following on your computer:
  * a Unity asset extraction tool like [AssetStudioModGUI](https://github.com/aelurum/AssetStudio/releases/latest) (Windows only) or [AssetRipper](https://github.com/assetripper/assetripper) (Linux, macOS, Windows)
  * an archive extraction software like [7-Zip](https://7-zip.org/), [The Unarchiver](https://apps.apple.com/us/app/the-unarchiver/id425424353) or [Ark](https://apps.kde.org/fr/ark/)

#### Steps
1. Launch *Pokémon Trading Card Game Pocket* on your Android device, then download the required additional data when prompted
2. Once the download is complete, close the game, then open X-/APK/S Extractor & Installer
3. Choose where to save the APK files, then select *Pokémon TCGP* from the menu and click `Save` to export an `.apks` file
4. Connect your Android device to a computer using a USB cable
5. From your computer, navigate to the directory on your phone where the `Pokémon TCGP.apks` file was saved, then copy it to a location of your choice on your computer
6. Open the `Pokémon TCGP.apks` file with your archive extraction software, then extract the `base.apk` and `split_bundledtree.apk` files from it
7. Open `base.apk` using your archive extraction software, then extract the `assets/bin/Data/` directory from it
8. Launch the Unity asset extraction tool, open the extracted `Data` directory, then locate and export the `src_cph_1001` file to a location of your choice. If the exported file has an extension (such as `.bytes` or `.txt`), rename the file to remove it
9. Open `split_bundledtree.apk` with your archive extraction software, then extract the `assets/assetpack/blob/` and `assets/assetpack/index/` directories into the same location as `src_cph_1001`
10. From your computer, navigate to the `Android/data/jp.pokemon.pokemontcgp/files/Sharin.Resources/Default/` directory on your phone, then copy the `blob/` and `index/` directories over the existing ones on your computer. If prompted, agree to write to these directories and replace any existing files

### Running aladump
> [!IMPORTANT]
> aladump is a command-line program and must be run in a terminal.

To decrypt the game's assets, run `aladump <indir>`, where `<indir>` is the directory containing the following items:
* the `blob/` directory
* the `index/` directory
* the `src_cph_1001` file

The decrypted Unity assets are written to a newly created `output/` directory. To read them, you may need to specify a Unity version in your asset extraction software (AssetStudioMod: `Options > Import options > Specify Unity version`; AssetRipper: `View > Settings > Import > Default Version`), depending on the game version:
* 1.7.0: `6000.0.69f1`
* from 1.5.0 to 1.6.0: `2022.3.62f2`
* from 1.3.0 to 1.4.1: `2022.3.58f1`
* from 1.2.0 to 1.2.5: `2022.3.56f1`
* from 1.0.2 to 1.1.2: `2022.3.22f1`

Then open the `output/` directory with your software. You can now browse and export the game's decrypted assets.

## Building
### Dependencies
* `clang` or `gcc`
* `make`

### Steps
1. If you don't already have them, install the dependencies
2. Clone this repository by running `git clone https://github.com/SombrAbsol/aladump`, or [download the ZIP archive](https://github.com/SombrAbsol/aladump/archive/refs/heads/main.zip) and extract it
3. Go to the repository directory and build the executable by running `make`

> [!TIP]
> Running `make` or `make release` will generate a release build. The downloadable releases are static builds generated using this recipe. If you want to generate a native or a debug build, run `make native` or `make debug`. Native builds are optimized for your specific CPU for better performance but may not be compatible with other systems, while debug builds include debugging symbols that help diagnose issues but run slower.
>
> Unix-like operating systems (such as Linux and macOS) can run `sudo make install` to install aladump system-wide, preferably after building a release or native build. Use `sudo make uninstall` to remove it.
>
> If you need to rebuild the program, run `make clean` or delete the `build` directory.

## Credits
* aladump by [SombrAbsol](https://github.com/SombrAbsol)
* Based on the research and a Python program made by [ElChicoEevee](https://github.com/ChicoEevee) and [LukeFZ](https://github.com/LukeFZ)
* [Yann Collet](https://github.com/Cyan4973) for the [xxHash project](https://github.com/Cyan4973/xxHash), that aladump reuses
* [Daniel J. Bernstein](https://cr.yp.to/djb.html) for designing the [ChaCha20 stream cipher](https://cr.yp.to/chacha.html) 

## License
aladump is free software. You can redistribute it and/or modify it under the [terms of the Expat License](/LICENSE) as published by the Massachusetts Institute of Technology.

This software source code also uses derivatives from third-party code, which remain subject to their respective original licenses. See [THIRD_PARTY_NOTICES.md](/THIRD_PARTY_NOTICES.md) and per-file headers for details.
