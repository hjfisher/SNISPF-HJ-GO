#!/bin/sh
set -e

curl -sSL -o .windivert_dl.zip https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
rm -rf windivert .windivert_dl
mkdir -p windivert .windivert_dl

if command -v unzip >/dev/null; then
  unzip -o .windivert_dl.zip -d .windivert_dl
else
  python3 -c "import zipfile; zipfile.ZipFile('.windivert_dl.zip').extractall('.windivert_dl')"
fi

find .windivert_dl -name 'WinDivert.dll' -path '*x64*' -exec cp {} windivert/ ';'
find .windivert_dl -name 'WinDivert64.sys' -exec cp {} windivert/ ';'
find .windivert_dl -name 'WinDivert32.sys' -exec cp {} windivert/ ';'

echo '--- windivert bundle ---'
ls -la windivert/
