#!/bin/sh

remove() {
  systemctl disable --now guard.timer ||: &> /dev/null
  systemctl disable guard.service ||: &> /dev/null
  echo hello
}

action="$1"
if  [ "$1" = "configure" ] && [ -z "$2" ]; then
  action="remove"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
  # deb passes $1=configure $2=<current version>
  action="upgrade"
fi

case "$action" in
  "0" | "remove")
    printf "\033[32mRemoving guard service and timer\033[0m\n"
    remove
    ;;
  "1" | "upgrade")
    ;;
  *)
    printf "\033[32mRemoving guard service and timer\033[0m\n"
    remove
    ;;
esac