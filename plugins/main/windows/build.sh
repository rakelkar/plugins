#!/usr/bin/env bash
set -e

OUTDIR="${PWD}/bin/windows"
mkdir -p ${OUTDIR}

PLUGINS="plugins/main/windows/*"
for d in $PLUGINS; do
	if [ -d "$d" ]; then
		plugin="$(basename "$d")"
		echo "  $plugin.exe"
		# use go install so we don't duplicate work
		if [ -n "$FASTBUILD" ]
		then
			GOBIN=${OUTDIR} go install -pkgdir $GOPATH/pkg "$@" $REPO_PATH/$d
		else
			go build -o "${OUTDIR}/$plugin.exe" -pkgdir "$GOPATH/pkg" "$@" "$REPO_PATH/$d"
		fi
	fi
done
