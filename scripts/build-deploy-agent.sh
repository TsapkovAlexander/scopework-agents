#!/usr/bin/env bash
#
# Выпуск агента развёртывания: сборка, воспроизведение, проверка.
#
#   scripts/build-deploy-agent.sh build [--out КАТАЛОГ]
#       выпуск в контейнере Go, закреплённом по digest; по умолчанию
#       КАТАЛОГ — dist/agent-releases
#   scripts/build-deploy-agent.sh build --local [--out КАТАЛОГ]
#       то же на своём Go — для стенда; release.json помечает его
#       невоспроизводимым
#   scripts/build-deploy-agent.sh reproduce
#       две сборки из копий исходников в разных путях, каждая в чистом
#       контейнере; хеши обязаны совпасть, иначе код 1
#   scripts/build-deploy-agent.sh verify <каталог выпуска>
#       пересобрать из этого дерева и сравнить с SHA256SUMS выпуска
#
# Выпуск ложится в <КАТАЛОГ>/deploy-agent/<версия>/: бинари linux/amd64 и
# linux/arm64, SHA256SUMS, release.json. Ту же раскладку читает платформа, так
# что каталог выкладывается на сервер как есть. Подпись и её проверка —
# scripts/deploy/sign-agent-release.mjs.
#
# ЗАЧЕМ ВОСПРОИЗВОДИМОСТЬ. Подпись офлайн-ключом (ADR-0082) заверяет
# конкретный файл, а открытый код (ADR-0096) чего-то стоит, только если любой
# может собрать из него тот же файл и сравнить хеш. Поэтому всё, от чего бинарь
# зависит, закреплено здесь, а всё, что отличается от машины к машине, из него
# убрано:
#   - компилятор — образ Go по digest индекса, а не по тегу: тег плавает, и
#     «тот же golang:1.26» через месяц даёт другой бинарь;
#   - --platform linux/amd64 — один и тот же компилятор на Mac и на Linux;
#     кросс-компиляция в arm64 идёт из него же;
#   - CGO_ENABLED=0 — иначе бинарь тянет glibc сборочного образа и падает у
#     клиента с ошибкой загрузчика;
#   - GOTOOLCHAIN=local — Go не скачивает другой компилятор по строке в go.mod;
#   - -trimpath — пути сборочной машины не попадают в бинарь;
#   - -buildvcs=false — сведения системы контроля версий тоже: выпуск из
#     экспорта (ADR-0096) и из монорепо обязан совпасть;
#   - -buildid= — пустой идентификатор сборки вместо производного от путей;
#   - -mod=readonly — зависимости только из go.mod, без тихой правки;
#   - ни времени, ни случайных чисел в ldflags.
# Каждая сборка — в свежем контейнере с --network none: ни кеша, ни загрузок.
#
# ВЕРСИЯ — ТОЛЬКО ИЗ apps/deploy-agent/VERSION, аргументом и окружением её не
# переопределить: бинарь с номером, которого нет в файле, разошёлся бы с
# записью об изменениях, а агент на хосте отклонял бы обновление или качал его
# по кругу. Разряды и порядок подъёма — apps/deploy-agent/VERSION.md.
#
# КЛЮЧИ ВШИВАЮТСЯ ИЗ apps/deploy-agent/trust. Ключи выпуска (trust/release) —
# всегда, пустой список тоже: так гейт видит, что символ существует. Корни
# состояния (trust/state) — только если они там есть. Компоновщик Go молча
# пропускает -X для несуществующего символа, поэтому после сборки бинарь сам
# печатает вшитые отпечатки (version --trust), и они сверяются с каталогом.
# Бинарь, который отпечатков не печатает, не выпускается.
#
# Скрипт опирается только на свой каталог и на Docker: он же лежит в
# открытом экспорте кода агента и обязан работать там без монорепо.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_DIR="$ROOT/apps/deploy-agent"

# 1.26.5 — тот же выпуск Go, что у разработчиков, и тот, что требует go.mod
# (go 1.26). Digest — индекса образа: он фиксирует обе архитектуры разом.
# Смена образа меняет бинарь, значит — новая версия агента.
GO_IMAGE="golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2"

ARCHES="amd64 arm64"

# Канонический std-base64 ровно 32 байт: 43 знака и «=». Последний знак несёт
# 4 бита данных и два нулевых — отсюда его короткий алфавит.
KEY_RE='^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$'

# Компиляция одна на все пути — в контейнере и на своём Go. Переменные
# раскрывает sh, которому её передают.
# shellcheck disable=SC2016
COMPILE='set -eu
for arch in amd64 arm64; do
  GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -mod=readonly \
    -ldflags "$AGENT_LDFLAGS" -o "$AGENT_OUT/deploy-agent-linux-$arch" .
done'

die() {
  echo "ОШИБКА: $*" >&2
  exit 1
}

usage() {
  sed -n '3,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1
  fi
}

sha256_file() {
  sha256_stdin < "$1"
}

# Первые 16 hex sha256 сырых байт ключа — тот же отпечаток, что печатают
# version --trust и install.sh.
fingerprint() {
  printf '%s' "$1" | base64 -d | sha256_stdin | cut -c1-16
}

# Ключи каталога через запятую, в порядке имён файлов (LC_ALL=C: порядок не
# должен зависеть от локали машины).
read_keys() {
  local dir="$1" keys="" file key
  [ -d "$dir" ] || return 0
  while IFS= read -r file; do
    [ "$(grep -c '' "$file")" = 1 ] || die "${file#"$ROOT"/}: ключ — одна строка std-base64"
    key="$(head -n 1 "$file" | tr -d '\r')"
    printf '%s' "$key" | grep -Eq "$KEY_RE" \
      || die "${file#"$ROOT"/}: не std-base64 открытого ключа Ed25519 (32 байта)"
    keys="${keys:+$keys,}$key"
  done < <(find "$dir" -maxdepth 1 -type f -name '*.pub' | LC_ALL=C sort)
  printf '%s' "$keys"
}

fingerprints() {
  local list="$1" out="" key
  local IFS=,
  for key in $list; do
    out="${out:+$out,}$(fingerprint "$key")"
  done
  printf '%s' "$out"
}

# Хеш исходников бинаря — тот же, что хранит apps/deploy-agent/VERSION.lock
# (scripts/check-agent-versions.mjs): sha256 строк «путь\0sha256 файла» по
# *.go без тестов, go.mod, go.sum и trust/**/*.pub. По нему release.json
# связывает выпуск с кодом без обращения к истории репозитория.
source_hash() {
  (
    cd "$1"
    find . -type f \( \( -name '*.go' ! -name '*_test.go' \) -o -name go.mod -o -name go.sum \
      -o \( -path './trust/*' -name '*.pub' \) \) \
      | sed 's|^\./||' | LC_ALL=C sort \
      | while IFS= read -r f; do printf '%s\0%s\n' "$f" "$(sha256_file "$f")"; done
  ) | sha256_stdin
}

VERSION="$(tr -d ' \t\n\r' < "$ROOT/apps/deploy-agent/VERSION")"
printf '%s' "$VERSION" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' \
  || die "версия агента должна быть MAJOR.MINOR.PATCH, в apps/deploy-agent/VERSION «${VERSION}»"

RELEASE_KEYS="$(read_keys "$AGENT_DIR/trust/release")"
STATE_ROOTS="$(read_keys "$AGENT_DIR/trust/state")"
RELEASE_FPS="$(fingerprints "$RELEASE_KEYS")"
STATE_FPS="$(fingerprints "$STATE_ROOTS")"

LDFLAGS="-s -w -buildid= -X main.Version=$VERSION"
LDFLAGS="$LDFLAGS -X tracedocs.ru/deploy-agent/internal/agent.trustedKeysRaw=$RELEASE_KEYS"
if [ -n "$STATE_ROOTS" ]; then
  LDFLAGS="$LDFLAGS -X tracedocs.ru/deploy-agent/internal/agent.trustedStateRootsRaw=$STATE_ROOTS"
fi

TMP=""
cleanup() {
  if [ -n "$TMP" ]; then rm -rf "$TMP"; fi
}
trap cleanup EXIT

need_docker() {
  docker info >/dev/null 2>&1 \
    || die "Docker не отвечает: и сборка выпуска, и проверка вшитых отпечатков идут в контейнере Go"
}

# <каталог исходников агента> <каталог вывода>. Исходники монтируются по тому
# же пути, что на машине: две сборки из разных путей обязаны дать один бинарь,
# и проверять это надо путями, которые действительно разные.
compile_in_container() {
  local src="$1" out="$2"
  docker run --rm --platform linux/amd64 --network none \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e GOCACHE=/tmp/go-cache -e GOPATH=/tmp/go \
    -e CGO_ENABLED=0 -e GOTOOLCHAIN=local \
    -e AGENT_LDFLAGS="$LDFLAGS" -e AGENT_OUT=/out \
    -v "$src:$src:ro" -v "$out:/out" -w "$src" \
    "$GO_IMAGE" sh -c "$COMPILE"
}

compile_local() {
  local src="$1" out="$2"
  (cd "$src" && CGO_ENABLED=0 GOTOOLCHAIN=local AGENT_LDFLAGS="$LDFLAGS" AGENT_OUT="$out" sh -c "$COMPILE")
}

write_sums() {
  local dir="$1" arch
  for arch in $ARCHES; do
    printf '%s  %s\n' "$(sha256_file "$dir/deploy-agent-linux-$arch")" "deploy-agent-linux-$arch"
  done
}

json_list() {
  local list="$1" out="" item
  local IFS=,
  for item in $list; do
    out="${out:+$out, }\"$item\""
  done
  printf '[%s]' "$out"
}

# Без времени сборки: иначе два выпуска из одного кода различались бы файлом,
# который лежит рядом с подписанными бинарями.
write_release_json() {
  local file="$1" image="$2" reproducible="$3"
  {
    printf '{\n'
    printf '  "version": "%s",\n' "$VERSION"
    printf '  "goImage": %s,\n' "$image"
    printf '  "sourceHash": "%s",\n' "$SOURCE_HASH"
    printf '  "releaseKeys": %s,\n' "$(json_list "$RELEASE_FPS")"
    printf '  "stateRoots": %s,\n' "$(json_list "$STATE_FPS")"
    printf '  "reproducible": %s\n' "$reproducible"
    printf '}\n'
  } > "$file"
}

# Доказательство, что -X сработал: собранный бинарь сам печатает то, что в нём
# зашито, и это обязано совпасть с trust/*.pub. Запускается amd64 — он и
# собран тем же компилятором, что arm64.
check_trust() {
  local dir="$1" report expected state_line
  report="$(docker run --rm --platform linux/amd64 --network none \
    -v "$dir:/release:ro" "$GO_IMAGE" /release/deploy-agent-linux-amd64 version --trust)" \
    || die "бинарь не запустился для проверки отпечатков (version --trust)"
  if ! printf '%s\n' "$report" | grep -q '^version='; then
    die "бинарь не выводит отпечатки (version --trust ответил «${report}»): без них нельзя проверить, какие ключи в нём зашиты"
  fi
  expected="$(printf 'version=%s\nrelease_keys=%s' "$VERSION" "$RELEASE_FPS")"
  # Строку state_roots печатает код корней подписи состояния (штаб Г,
  # internal/agent/state_trust.go); до него бинарь её не выводит. Корни в
  # trust/state без этой строки — красный: доказать, что -X их вшил, нечем.
  state_line="$(printf '%s\n' "$report" | grep '^state_roots=' || true)"
  if [ "$(printf '%s\n' "$report" | grep -v '^state_roots=')" != "$expected" ]; then
    printf 'в бинаре:\n%s\nожидалось по apps/deploy-agent/trust:\n%s\n' "$report" "$expected" >&2
    die "вшитые ключи не совпадают с каталогом trust: -X не сработал или сборка не та"
  fi
  if [ -n "$STATE_FPS" ] && [ "$state_line" != "state_roots=$STATE_FPS" ]; then
    printf 'в бинаре: %s\nожидалось: state_roots=%s\n' "${state_line:-строки state_roots нет}" "$STATE_FPS" >&2
    die "в trust/state есть корни, а бинарь их не показывает: -X не сработал или в агенте нет кода корней"
  fi
  if [ -z "$STATE_FPS" ] && [ -n "$state_line" ] && [ "$state_line" != "state_roots=" ]; then
    die "в бинаре корни состояния (${state_line}), которых нет в trust/state"
  fi
  echo "· отпечатки в бинаре совпали с trust: ключи выпуска [${RELEASE_FPS:-нет}], корни состояния [${STATE_FPS:-нет}]"
}

cmd_build() {
  local out="$ROOT/dist/agent-releases" local_build=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --out)
        [ $# -ge 2 ] || usage
        out="$2"
        shift 2
        ;;
      --local)
        local_build=1
        shift
        ;;
      *) usage ;;
    esac
  done

  need_docker
  mkdir -p "$out"
  out="$(cd "$out" && pwd)"
  local release_dir="$out/deploy-agent/$VERSION"
  # Подписи в каталоге выпуска относятся к прежним файлам: молча пересобранный
  # бинарь рядом со старой подписью агент с ключом отверг бы у всех клиентов.
  [ ! -e "$release_dir" ] || die "каталог выпуска уже есть: $release_dir — удалите его или укажите --out"

  TMP="$(mktemp -d)"
  local staging="$TMP/release"
  mkdir -p "$staging"

  echo "· версия $VERSION"
  if [ "$local_build" = 1 ]; then
    echo "· сборка на своём Go ($(go version)) — выпуск невоспроизводим, только для стенда"
    compile_local "$AGENT_DIR" "$staging"
  else
    echo "· сборка в $GO_IMAGE"
    compile_in_container "$AGENT_DIR" "$staging"
  fi
  check_trust "$staging"

  SOURCE_HASH="$(source_hash "$AGENT_DIR")"
  write_sums "$staging" > "$staging/SHA256SUMS"
  if [ "$local_build" = 1 ]; then
    write_release_json "$staging/release.json" null false
  else
    write_release_json "$staging/release.json" "\"$GO_IMAGE\"" true
  fi

  mkdir -p "$out/deploy-agent"
  mv "$staging" "$release_dir"

  echo
  echo "Выпуск: $release_dir"
  sed 's/^/  /' "$release_dir/SHA256SUMS"
  echo
  if [ -n "$RELEASE_KEYS" ]; then
    echo "Дальше — подпись офлайн-ключом для каждой архитектуры и проверка:"
    echo "  node scripts/deploy/sign-agent-release.mjs sign <ключ> <бинарь> $VERSION <arch>"
    echo "  node scripts/deploy/sign-agent-release.mjs verify $release_dir"
  else
    echo "Ключей выпуска в trust/release нет — выпуск неподписанный, агенты подпись не проверяют."
  fi
}

cmd_reproduce() {
  need_docker
  TMP="$(mktemp -d)"
  # Разные пути и разная глубина: -trimpath обязан убрать и то и другое.
  local first="$TMP/first/apps/deploy-agent"
  local second="$TMP/second/copy/of/tree/apps/deploy-agent"
  mkdir -p "$(dirname "$first")" "$(dirname "$second")" "$TMP/out-first" "$TMP/out-second"
  cp -R "$AGENT_DIR" "$first"
  cp -R "$AGENT_DIR" "$second"

  echo "· версия $VERSION, образ $GO_IMAGE"
  echo "· сборка 1 из $first"
  compile_in_container "$first" "$TMP/out-first"
  echo "· сборка 2 из $second"
  compile_in_container "$second" "$TMP/out-second"

  local arch a b failed=0
  echo
  for arch in $ARCHES; do
    a="$(sha256_file "$TMP/out-first/deploy-agent-linux-$arch")"
    b="$(sha256_file "$TMP/out-second/deploy-agent-linux-$arch")"
    if [ "$a" = "$b" ]; then
      echo "  $arch  $a  $b  совпали"
    else
      echo "  $arch  $a  $b  РАЗОШЛИСЬ"
      failed=1
    fi
  done
  echo
  [ "$failed" = 0 ] || die "сборка невоспроизводима: одна версия из одних исходников дала разные бинари"
  check_trust "$TMP/out-first"
  echo "Воспроизводимо: две сборки в разных путях дали одинаковые бинари."
}

cmd_verify() {
  [ $# -eq 1 ] || usage
  local dir="$1"
  [ -d "$dir" ] || die "нет каталога выпуска: $dir"
  dir="$(cd "$dir" && pwd)"
  local version
  version="$(basename "$dir")"
  [ "$version" = "$VERSION" ] \
    || die "выпуск $version, а в дереве $VERSION — проверять выпуск надо исходниками той же версии"
  [ -f "$dir/SHA256SUMS" ] || die "в выпуске нет SHA256SUMS: $dir"

  SOURCE_HASH="$(source_hash "$AGENT_DIR")"
  if [ -f "$dir/release.json" ]; then
    grep -q '"reproducible": true' "$dir/release.json" \
      || die "выпуск собран на своём Go (build --local) — воспроизводить нечего"
    local recorded
    recorded="$(sed -n 's/.*"sourceHash": *"\([0-9a-f]*\)".*/\1/p' "$dir/release.json")"
    [ "$recorded" = "$SOURCE_HASH" ] \
      || die "выпуск собран из других исходников (sourceHash ${recorded:-нет}, в дереве $SOURCE_HASH)"
  fi

  if [ "$(write_sums "$dir")" != "$(cat "$dir/SHA256SUMS")" ]; then
    die "бинари выпуска не совпадают с его же SHA256SUMS: $dir"
  fi

  need_docker
  TMP="$(mktemp -d)"
  echo "· пересборка $VERSION в $GO_IMAGE"
  compile_in_container "$AGENT_DIR" "$TMP"
  if [ "$(write_sums "$TMP")" != "$(cat "$dir/SHA256SUMS")" ]; then
    echo "в выпуске:" >&2
    cat "$dir/SHA256SUMS" >&2
    echo "пересобрано:" >&2
    write_sums "$TMP" >&2
    die "выпуск не воспроизводится из этого дерева"
  fi
  check_trust "$dir"
  echo "Выпуск $VERSION воспроизведён из этого дерева: SHA256SUMS совпали."
}

case "${1:-}" in
  build)
    shift
    cmd_build "$@"
    ;;
  reproduce)
    shift
    [ $# -eq 0 ] || usage
    cmd_reproduce
    ;;
  verify)
    shift
    cmd_verify "$@"
    ;;
  *) usage ;;
esac
