#!/bin/sh
set -e

while [ "$1" ]; do
    case "$1" in
        (--output)
            shift
            OUTPUT_DIR="$1"
            ;;
        (*) ;;
    esac
    shift
done

PACKAGE=krb5
SPEC_FILE=".copr/${PACKAGE}.spec"
RELTAG="$(git describe --tags --exact-match 2>/dev/null ||
          git symbolic-ref -q --short HEAD | head -n1)"
RELDIR="${PACKAGE}-$(rpmspec -q --qf '%{version}\n' "$SPEC_FILE" | head -n1)"
SRPM="$(rpmspec -q --qf '%{name}-%{version}-%{release}\n' "$SPEC_FILE" | head -n1).src.rpm"

./src/util/mkrel --nocheckout "$RELTAG" "$RELDIR"

RPMBUILD="$(pwd)/rpmbuild"
mkdir -p "${RPMBUILD}/BUILD"
mkdir -p "${RPMBUILD}/RPMS"
mkdir -p "${RPMBUILD}/SOURCES"
mkdir -p "${RPMBUILD}/SPECS"
mkdir -p "${RPMBUILD}/SRPMS"

cp "$SPEC_FILE" "${RPMBUILD}/SPECS/"
cp "${RELDIR}.tar.gz" "${RPMBUILD}/SOURCES/"
cp .copr/conf/* "${RPMBUILD}/SOURCES/"

cd "$RPMBUILD"
rpmbuild --define "_topdir $RPMBUILD" -bs "SPECS/${PACKAGE}.spec"
cp "SRPMS/$SRPM" "$OUTPUT_DIR"/
