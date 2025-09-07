#!/bin/bash

first=true
condition=""

while [[ $first = true || "$condition" != "q" ]]; do
    first=false

    # ================================
    # Grup
    # ================================
    echo -n "Enter group name: "
    read group_name

    while getent group "$group_name" > /dev/null; do
        echo "[WARNING] Grupul '$group_name' deja există. Încearcă alt nume."
        echo -n "Enter group name: "
        read group_name
    done

    groupadd "$group_name"
    echo "[INFO] Grup '$group_name' creat."

    # ================================
    # User
    # ================================
    echo -n "Enter user name: "
    read ans

    while id "$ans" &>/dev/null; do
        echo "[WARNING] Utilizatorul '$ans' deja există. Încearcă alt nume."
        echo -n "Enter user name: "
        read ans
    done

    useradd -m -d "/home/$ans" -s /bin/bash -g "$group_name" "$ans"
    echo "[INFO] Utilizator '$ans' creat în grupul '$group_name'."

    # ================================
    # Parolă implicită
    # ================================
    echo -e "$ans\n$ans" | passwd "$ans" >/dev/null 2>&1
    echo "[INFO] Parola setată implicit la numele userului."

    # ================================
    # Permisiuni home
    # ================================
    chown -R "$ans:$group_name" "/home/$ans"
    chmod 770 "/home/$ans"
    echo "[INFO] Permisiuni setate pentru /home/$ans"

    # ================================
    # Continuare / Quit
    # ================================
    echo -n "Enter q to quit or any key to continue: "
    read condition
done
