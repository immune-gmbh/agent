#!/bin/sh

install() {
    systemctl unmask guard.service ||: &> /dev/null
    systemctl preset guard.service ||: &> /dev/null
    systemctl enable guard.service ||: &> /dev/null
    systemctl enable --now guard.timer ||: &> /dev/null
    systemctl daemon-reload ||: &> /dev/null
}

action="$1"
if  [ "$1" = "configure" ] && [ -z "$2" ]; then
  action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
    # deb passes $1=configure $2=<current version>
    action="upgrade"
fi

case "$action" in
  "1" | "install")
    printf "\033[32mInstalling guard service and timer\033[0m\n"
    install
    ;;
  "2" | "upgrade")
    printf "\033[32mInstalling guard service and timer\033[0m\n"
    install
    ;;
  *)
    printf "\033[32mInstalling guard service and timer\033[0m\n"
    install
    ;;
esac