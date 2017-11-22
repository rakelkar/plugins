#!/usr/bin/env bash
set -e

export GOOS=windows
OUTDIR="${PWD}/bin/windows"
mkdir -p ${OUTDIR}

echo "Building plugins for ${GOOS}"
PLUGINS="plugins/main/windows/*"
for d in $PLUGINS; do
	if [ -d "$d" ]; then
		plugin="$(basename "$d")"
		echo "  $plugin"
		# use go install so we don't duplicate work
		if [ -n "$FASTBUILD" ]
		then
			GOBIN=${OUTDIR} go install -pkgdir $GOPATH/pkg "$@" $REPO_PATH/$d
		else
			go build -o "${OUTDIR}/$plugin" -pkgdir "$GOPATH/pkg" "$@" "$REPO_PATH/$d"
		fi
	fi
done
